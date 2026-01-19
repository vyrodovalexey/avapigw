package routing

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// ExactPathMatcher Tests
// =============================================================================

func TestNewExactPathMatcher(t *testing.T) {
	matcher := NewExactPathMatcher("/api/v1/users")
	assert.NotNil(t, matcher)
	assert.Equal(t, "/api/v1/users", matcher.path)
}

func TestExactPathMatcher_Match(t *testing.T) {
	tests := []struct {
		name        string
		matcherPath string
		inputPath   string
		wantMatch   bool
		wantCapture map[string]string
	}{
		{
			name:        "exact match",
			matcherPath: "/api/v1/users",
			inputPath:   "/api/v1/users",
			wantMatch:   true,
			wantCapture: nil,
		},
		{
			name:        "non-match different path",
			matcherPath: "/api/v1/users",
			inputPath:   "/api/v1/orders",
			wantMatch:   false,
			wantCapture: nil,
		},
		{
			name:        "non-match with trailing slash",
			matcherPath: "/api/v1/users",
			inputPath:   "/api/v1/users/",
			wantMatch:   false,
			wantCapture: nil,
		},
		{
			name:        "match with trailing slash in pattern",
			matcherPath: "/api/v1/users/",
			inputPath:   "/api/v1/users/",
			wantMatch:   true,
			wantCapture: nil,
		},
		{
			name:        "non-match prefix only",
			matcherPath: "/api/v1/users",
			inputPath:   "/api/v1",
			wantMatch:   false,
			wantCapture: nil,
		},
		{
			name:        "non-match longer path",
			matcherPath: "/api/v1/users",
			inputPath:   "/api/v1/users/123",
			wantMatch:   false,
			wantCapture: nil,
		},
		{
			name:        "match root path",
			matcherPath: "/",
			inputPath:   "/",
			wantMatch:   true,
			wantCapture: nil,
		},
		{
			name:        "non-match root vs non-root",
			matcherPath: "/",
			inputPath:   "/api",
			wantMatch:   false,
			wantCapture: nil,
		},
		{
			name:        "match empty path",
			matcherPath: "",
			inputPath:   "",
			wantMatch:   true,
			wantCapture: nil,
		},
		{
			name:        "case sensitive match",
			matcherPath: "/API/V1/Users",
			inputPath:   "/api/v1/users",
			wantMatch:   false,
			wantCapture: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := NewExactPathMatcher(tt.matcherPath)
			gotMatch, gotCapture := matcher.Match(tt.inputPath)
			assert.Equal(t, tt.wantMatch, gotMatch)
			assert.Equal(t, tt.wantCapture, gotCapture)
		})
	}
}

func TestExactPathMatcher_Type(t *testing.T) {
	matcher := NewExactPathMatcher("/api")
	assert.Equal(t, "Exact", matcher.Type())
}

// =============================================================================
// PrefixPathMatcher Tests
// =============================================================================

func TestNewPrefixPathMatcher(t *testing.T) {
	matcher := NewPrefixPathMatcher("/api")
	assert.NotNil(t, matcher)
	assert.Equal(t, "/api", matcher.prefix)
}

func TestPrefixPathMatcher_Match(t *testing.T) {
	tests := []struct {
		name         string
		matcherPath  string
		inputPath    string
		wantMatch    bool
		wantCaptures map[string]string
	}{
		{
			name:         "prefix match with subpath",
			matcherPath:  "/api",
			inputPath:    "/api/v1/users",
			wantMatch:    true,
			wantCaptures: nil,
		},
		{
			name:         "prefix match exact",
			matcherPath:  "/api",
			inputPath:    "/api",
			wantMatch:    true,
			wantCaptures: nil,
		},
		{
			name:         "prefix match with slash boundary",
			matcherPath:  "/api",
			inputPath:    "/api/",
			wantMatch:    true,
			wantCaptures: nil,
		},
		{
			name:         "non-match path boundary - apikey should not match /api",
			matcherPath:  "/api",
			inputPath:    "/apikey",
			wantMatch:    false,
			wantCaptures: nil,
		},
		{
			name:         "non-match different prefix",
			matcherPath:  "/api",
			inputPath:    "/web/api",
			wantMatch:    false,
			wantCaptures: nil,
		},
		{
			name:         "prefix ending with slash matches subpath",
			matcherPath:  "/api/",
			inputPath:    "/api/v1",
			wantMatch:    true,
			wantCaptures: nil,
		},
		{
			name:         "prefix ending with slash matches exact",
			matcherPath:  "/api/",
			inputPath:    "/api/",
			wantMatch:    true,
			wantCaptures: nil,
		},
		{
			name:         "prefix ending with slash non-match without slash",
			matcherPath:  "/api/",
			inputPath:    "/api",
			wantMatch:    false,
			wantCaptures: nil,
		},
		{
			name:         "root prefix matches all",
			matcherPath:  "/",
			inputPath:    "/anything/here",
			wantMatch:    true,
			wantCaptures: nil,
		},
		{
			name:         "empty prefix matches empty",
			matcherPath:  "",
			inputPath:    "",
			wantMatch:    true,
			wantCaptures: nil,
		},
		{
			name:         "empty prefix matches any path",
			matcherPath:  "",
			inputPath:    "/api/v1",
			wantMatch:    true,
			wantCaptures: nil,
		},
		{
			name:         "longer prefix than path",
			matcherPath:  "/api/v1/users",
			inputPath:    "/api",
			wantMatch:    false,
			wantCaptures: nil,
		},
		{
			name:         "prefix with multiple segments",
			matcherPath:  "/api/v1",
			inputPath:    "/api/v1/users/123",
			wantMatch:    true,
			wantCaptures: nil,
		},
		{
			name:         "prefix boundary check with similar paths",
			matcherPath:  "/api/v1",
			inputPath:    "/api/v10",
			wantMatch:    false,
			wantCaptures: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := NewPrefixPathMatcher(tt.matcherPath)
			gotMatch, gotCaptures := matcher.Match(tt.inputPath)
			assert.Equal(t, tt.wantMatch, gotMatch)
			assert.Equal(t, tt.wantCaptures, gotCaptures)
		})
	}
}

func TestPrefixPathMatcher_Type(t *testing.T) {
	matcher := NewPrefixPathMatcher("/api")
	assert.Equal(t, "PathPrefix", matcher.Type())
}

// =============================================================================
// RegexPathMatcher Tests
// =============================================================================

func TestNewRegexPathMatcher(t *testing.T) {
	tests := []struct {
		name        string
		pattern     string
		wantErr     bool
		errContains string
	}{
		{
			name:    "valid simple regex",
			pattern: "/api/v[0-9]+/users",
			wantErr: false,
		},
		{
			name:    "valid regex with capture groups",
			pattern: "/api/v([0-9]+)/users/([0-9]+)",
			wantErr: false,
		},
		{
			name:    "valid regex with named capture groups",
			pattern: "/api/v(?P<version>[0-9]+)/users/(?P<id>[0-9]+)",
			wantErr: false,
		},
		{
			name:        "invalid regex - unclosed bracket",
			pattern:     "/api/v[0-9+/users",
			wantErr:     true,
			errContains: "error parsing regexp",
		},
		{
			name:        "invalid regex - bad escape",
			pattern:     "/api/\\",
			wantErr:     true,
			errContains: "error parsing regexp",
		},
		{
			name:    "empty pattern is valid",
			pattern: "",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher, err := NewRegexPathMatcher(tt.pattern)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				assert.Nil(t, matcher)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, matcher)
				assert.Equal(t, tt.pattern, matcher.pattern)
			}
		})
	}
}

func TestRegexPathMatcher_Match(t *testing.T) {
	tests := []struct {
		name         string
		pattern      string
		inputPath    string
		wantMatch    bool
		wantCaptures map[string]string
	}{
		{
			name:         "simple regex match",
			pattern:      "/api/v[0-9]+/users",
			inputPath:    "/api/v1/users",
			wantMatch:    true,
			wantCaptures: map[string]string{},
		},
		{
			name:         "simple regex non-match",
			pattern:      "/api/v[0-9]+/users",
			inputPath:    "/api/vX/users",
			wantMatch:    false,
			wantCaptures: nil,
		},
		{
			name:         "regex with unnamed capture groups",
			pattern:      "/api/v([0-9]+)/users/([0-9]+)",
			inputPath:    "/api/v2/users/123",
			wantMatch:    true,
			wantCaptures: map[string]string{},
		},
		{
			name:      "regex with named capture groups",
			pattern:   "/api/v(?P<version>[0-9]+)/users/(?P<id>[0-9]+)",
			inputPath: "/api/v2/users/456",
			wantMatch: true,
			wantCaptures: map[string]string{
				"version": "2",
				"id":      "456",
			},
		},
		{
			name:      "regex with single named capture",
			pattern:   "/users/(?P<userId>[a-zA-Z0-9-]+)",
			inputPath: "/users/abc-123-def",
			wantMatch: true,
			wantCaptures: map[string]string{
				"userId": "abc-123-def",
			},
		},
		{
			name:         "regex partial match in path",
			pattern:      "/api",
			inputPath:    "/api/v1/users",
			wantMatch:    true,
			wantCaptures: map[string]string{},
		},
		{
			name:         "regex anchored start",
			pattern:      "^/api/v1$",
			inputPath:    "/api/v1",
			wantMatch:    true,
			wantCaptures: map[string]string{},
		},
		{
			name:         "regex anchored non-match",
			pattern:      "^/api/v1$",
			inputPath:    "/api/v1/users",
			wantMatch:    false,
			wantCaptures: nil,
		},
		{
			name:         "regex with optional segment",
			pattern:      "/api/v1(/users)?",
			inputPath:    "/api/v1",
			wantMatch:    true,
			wantCaptures: map[string]string{},
		},
		{
			name:         "regex with optional segment matched",
			pattern:      "/api/v1(/users)?",
			inputPath:    "/api/v1/users",
			wantMatch:    true,
			wantCaptures: map[string]string{},
		},
		{
			name:         "regex wildcard",
			pattern:      "/api/.*",
			inputPath:    "/api/anything/here/123",
			wantMatch:    true,
			wantCaptures: map[string]string{},
		},
		{
			name:         "empty pattern matches empty path",
			pattern:      "",
			inputPath:    "",
			wantMatch:    true,
			wantCaptures: map[string]string{},
		},
		{
			name:         "empty pattern matches any path",
			pattern:      "",
			inputPath:    "/api/v1",
			wantMatch:    true,
			wantCaptures: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher, err := NewRegexPathMatcher(tt.pattern)
			require.NoError(t, err)

			gotMatch, gotCaptures := matcher.Match(tt.inputPath)
			assert.Equal(t, tt.wantMatch, gotMatch)
			if tt.wantCaptures != nil {
				assert.Equal(t, tt.wantCaptures, gotCaptures)
			}
		})
	}
}

func TestRegexPathMatcher_Type(t *testing.T) {
	matcher, err := NewRegexPathMatcher("/api/.*")
	require.NoError(t, err)
	assert.Equal(t, "RegularExpression", matcher.Type())
}

// =============================================================================
// SimpleMethodMatcher Tests
// =============================================================================

func TestNewSimpleMethodMatcher(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		wantMethod string
	}{
		{
			name:       "uppercase method",
			method:     "GET",
			wantMethod: "GET",
		},
		{
			name:       "lowercase method converted to uppercase",
			method:     "get",
			wantMethod: "GET",
		},
		{
			name:       "mixed case method converted to uppercase",
			method:     "GeT",
			wantMethod: "GET",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := NewSimpleMethodMatcher(tt.method)
			assert.NotNil(t, matcher)
			assert.Equal(t, tt.wantMethod, matcher.method)
		})
	}
}

func TestSimpleMethodMatcher_Match(t *testing.T) {
	tests := []struct {
		name          string
		matcherMethod string
		inputMethod   string
		wantMatch     bool
	}{
		{
			name:          "exact match uppercase",
			matcherMethod: "GET",
			inputMethod:   "GET",
			wantMatch:     true,
		},
		{
			name:          "case insensitive match - lowercase input",
			matcherMethod: "GET",
			inputMethod:   "get",
			wantMatch:     true,
		},
		{
			name:          "case insensitive match - mixed case input",
			matcherMethod: "POST",
			inputMethod:   "PoSt",
			wantMatch:     true,
		},
		{
			name:          "non-match different method",
			matcherMethod: "GET",
			inputMethod:   "POST",
			wantMatch:     false,
		},
		{
			name:          "match PUT method",
			matcherMethod: "PUT",
			inputMethod:   "put",
			wantMatch:     true,
		},
		{
			name:          "match DELETE method",
			matcherMethod: "DELETE",
			inputMethod:   "delete",
			wantMatch:     true,
		},
		{
			name:          "match PATCH method",
			matcherMethod: "PATCH",
			inputMethod:   "patch",
			wantMatch:     true,
		},
		{
			name:          "match OPTIONS method",
			matcherMethod: "OPTIONS",
			inputMethod:   "options",
			wantMatch:     true,
		},
		{
			name:          "match HEAD method",
			matcherMethod: "HEAD",
			inputMethod:   "head",
			wantMatch:     true,
		},
		{
			name:          "empty method non-match",
			matcherMethod: "GET",
			inputMethod:   "",
			wantMatch:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := NewSimpleMethodMatcher(tt.matcherMethod)
			gotMatch := matcher.Match(tt.inputMethod)
			assert.Equal(t, tt.wantMatch, gotMatch)
		})
	}
}

// =============================================================================
// MultiMethodMatcher Tests
// =============================================================================

func TestNewMultiMethodMatcher(t *testing.T) {
	tests := []struct {
		name        string
		methods     []string
		wantMethods map[string]bool
	}{
		{
			name:    "single method",
			methods: []string{"GET"},
			wantMethods: map[string]bool{
				"GET": true,
			},
		},
		{
			name:    "multiple methods",
			methods: []string{"GET", "POST", "PUT"},
			wantMethods: map[string]bool{
				"GET":  true,
				"POST": true,
				"PUT":  true,
			},
		},
		{
			name:    "lowercase methods converted to uppercase",
			methods: []string{"get", "post"},
			wantMethods: map[string]bool{
				"GET":  true,
				"POST": true,
			},
		},
		{
			name:        "empty methods",
			methods:     []string{},
			wantMethods: map[string]bool{},
		},
		{
			name:    "duplicate methods",
			methods: []string{"GET", "GET", "POST"},
			wantMethods: map[string]bool{
				"GET":  true,
				"POST": true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := NewMultiMethodMatcher(tt.methods)
			assert.NotNil(t, matcher)
			assert.Equal(t, tt.wantMethods, matcher.methods)
		})
	}
}

func TestMultiMethodMatcher_Match(t *testing.T) {
	tests := []struct {
		name        string
		methods     []string
		inputMethod string
		wantMatch   bool
	}{
		{
			name:        "match first method",
			methods:     []string{"GET", "POST", "PUT"},
			inputMethod: "GET",
			wantMatch:   true,
		},
		{
			name:        "match middle method",
			methods:     []string{"GET", "POST", "PUT"},
			inputMethod: "POST",
			wantMatch:   true,
		},
		{
			name:        "match last method",
			methods:     []string{"GET", "POST", "PUT"},
			inputMethod: "PUT",
			wantMatch:   true,
		},
		{
			name:        "case insensitive match",
			methods:     []string{"GET", "POST"},
			inputMethod: "get",
			wantMatch:   true,
		},
		{
			name:        "non-match method not in list",
			methods:     []string{"GET", "POST"},
			inputMethod: "DELETE",
			wantMatch:   false,
		},
		{
			name:        "empty methods list non-match",
			methods:     []string{},
			inputMethod: "GET",
			wantMatch:   false,
		},
		{
			name:        "single method match",
			methods:     []string{"DELETE"},
			inputMethod: "delete",
			wantMatch:   true,
		},
		{
			name:        "all common methods",
			methods:     []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"},
			inputMethod: "PATCH",
			wantMatch:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := NewMultiMethodMatcher(tt.methods)
			gotMatch := matcher.Match(tt.inputMethod)
			assert.Equal(t, tt.wantMatch, gotMatch)
		})
	}
}

// =============================================================================
// ExactHeaderMatcher Tests
// =============================================================================

func TestNewExactHeaderMatcher(t *testing.T) {
	tests := []struct {
		name      string
		header    string
		value     string
		wantName  string
		wantValue string
	}{
		{
			name:      "lowercase header name",
			header:    "content-type",
			value:     "application/json",
			wantName:  "content-type",
			wantValue: "application/json",
		},
		{
			name:      "uppercase header name converted to lowercase",
			header:    "Content-Type",
			value:     "application/json",
			wantName:  "content-type",
			wantValue: "application/json",
		},
		{
			name:      "mixed case header name converted to lowercase",
			header:    "X-Custom-Header",
			value:     "custom-value",
			wantName:  "x-custom-header",
			wantValue: "custom-value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := NewExactHeaderMatcher(tt.header, tt.value)
			assert.NotNil(t, matcher)
			assert.Equal(t, tt.wantName, matcher.name)
			assert.Equal(t, tt.wantValue, matcher.value)
		})
	}
}

func TestExactHeaderMatcher_Name(t *testing.T) {
	tests := []struct {
		name       string
		headerName string
		wantName   string
	}{
		{
			name:       "lowercase header",
			headerName: "content-type",
			wantName:   "content-type",
		},
		{
			name:       "uppercase header returns lowercase",
			headerName: "AUTHORIZATION",
			wantName:   "authorization",
		},
		{
			name:       "mixed case header returns lowercase",
			headerName: "X-Request-ID",
			wantName:   "x-request-id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := NewExactHeaderMatcher(tt.headerName, "value")
			assert.Equal(t, tt.wantName, matcher.Name())
		})
	}
}

func TestExactHeaderMatcher_Match(t *testing.T) {
	tests := []struct {
		name         string
		matcherValue string
		inputValue   string
		wantMatch    bool
	}{
		{
			name:         "exact match",
			matcherValue: "application/json",
			inputValue:   "application/json",
			wantMatch:    true,
		},
		{
			name:         "non-match different value",
			matcherValue: "application/json",
			inputValue:   "text/html",
			wantMatch:    false,
		},
		{
			name:         "case sensitive non-match",
			matcherValue: "application/json",
			inputValue:   "Application/JSON",
			wantMatch:    false,
		},
		{
			name:         "empty value match",
			matcherValue: "",
			inputValue:   "",
			wantMatch:    true,
		},
		{
			name:         "empty matcher non-match non-empty input",
			matcherValue: "",
			inputValue:   "some-value",
			wantMatch:    false,
		},
		{
			name:         "non-empty matcher non-match empty input",
			matcherValue: "some-value",
			inputValue:   "",
			wantMatch:    false,
		},
		{
			name:         "partial value non-match",
			matcherValue: "application/json",
			inputValue:   "application",
			wantMatch:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := NewExactHeaderMatcher("test-header", tt.matcherValue)
			gotMatch := matcher.Match(tt.inputValue)
			assert.Equal(t, tt.wantMatch, gotMatch)
		})
	}
}

// =============================================================================
// RegexHeaderMatcher Tests
// =============================================================================

func TestNewRegexHeaderMatcher(t *testing.T) {
	tests := []struct {
		name        string
		headerName  string
		pattern     string
		wantErr     bool
		wantName    string
		errContains string
	}{
		{
			name:       "valid regex pattern",
			headerName: "Content-Type",
			pattern:    "application/.*",
			wantErr:    false,
			wantName:   "content-type",
		},
		{
			name:       "valid complex regex",
			headerName: "Authorization",
			pattern:    "^Bearer [a-zA-Z0-9-_.]+$",
			wantErr:    false,
			wantName:   "authorization",
		},
		{
			name:        "invalid regex pattern",
			headerName:  "X-Custom",
			pattern:     "[invalid",
			wantErr:     true,
			errContains: "error parsing regexp",
		},
		{
			name:       "empty pattern is valid",
			headerName: "X-Empty",
			pattern:    "",
			wantErr:    false,
			wantName:   "x-empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher, err := NewRegexHeaderMatcher(tt.headerName, tt.pattern)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				assert.Nil(t, matcher)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, matcher)
				assert.Equal(t, tt.wantName, matcher.name)
			}
		})
	}
}

func TestRegexHeaderMatcher_Name(t *testing.T) {
	matcher, err := NewRegexHeaderMatcher("X-Custom-Header", ".*")
	require.NoError(t, err)
	assert.Equal(t, "x-custom-header", matcher.Name())
}

func TestRegexHeaderMatcher_Match(t *testing.T) {
	tests := []struct {
		name       string
		pattern    string
		inputValue string
		wantMatch  bool
	}{
		{
			name:       "regex match",
			pattern:    "application/.*",
			inputValue: "application/json",
			wantMatch:  true,
		},
		{
			name:       "regex non-match",
			pattern:    "application/.*",
			inputValue: "text/html",
			wantMatch:  false,
		},
		{
			name:       "bearer token match",
			pattern:    "^Bearer [a-zA-Z0-9-_.]+$",
			inputValue: "Bearer abc123-token.xyz",
			wantMatch:  true,
		},
		{
			name:       "bearer token non-match",
			pattern:    "^Bearer [a-zA-Z0-9-_.]+$",
			inputValue: "Basic abc123",
			wantMatch:  false,
		},
		{
			name:       "partial match in string",
			pattern:    "json",
			inputValue: "application/json",
			wantMatch:  true,
		},
		{
			name:       "anchored pattern match",
			pattern:    "^application/json$",
			inputValue: "application/json",
			wantMatch:  true,
		},
		{
			name:       "anchored pattern non-match",
			pattern:    "^application/json$",
			inputValue: "application/json; charset=utf-8",
			wantMatch:  false,
		},
		{
			name:       "empty pattern matches any",
			pattern:    "",
			inputValue: "anything",
			wantMatch:  true,
		},
		{
			name:       "empty pattern matches empty",
			pattern:    "",
			inputValue: "",
			wantMatch:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher, err := NewRegexHeaderMatcher("test-header", tt.pattern)
			require.NoError(t, err)
			gotMatch := matcher.Match(tt.inputValue)
			assert.Equal(t, tt.wantMatch, gotMatch)
		})
	}
}

// =============================================================================
// PresentHeaderMatcher Tests
// =============================================================================

func TestNewPresentHeaderMatcher(t *testing.T) {
	tests := []struct {
		name       string
		headerName string
		wantName   string
	}{
		{
			name:       "lowercase header",
			headerName: "x-custom-header",
			wantName:   "x-custom-header",
		},
		{
			name:       "uppercase header converted to lowercase",
			headerName: "AUTHORIZATION",
			wantName:   "authorization",
		},
		{
			name:       "mixed case header converted to lowercase",
			headerName: "X-Request-ID",
			wantName:   "x-request-id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := NewPresentHeaderMatcher(tt.headerName)
			assert.NotNil(t, matcher)
			assert.Equal(t, tt.wantName, matcher.name)
		})
	}
}

func TestPresentHeaderMatcher_Name(t *testing.T) {
	matcher := NewPresentHeaderMatcher("X-Custom-Header")
	assert.Equal(t, "x-custom-header", matcher.Name())
}

func TestPresentHeaderMatcher_Match(t *testing.T) {
	tests := []struct {
		name       string
		inputValue string
		wantMatch  bool
	}{
		{
			name:       "always returns true for any value",
			inputValue: "some-value",
			wantMatch:  true,
		},
		{
			name:       "always returns true for empty value",
			inputValue: "",
			wantMatch:  true,
		},
		{
			name:       "always returns true for complex value",
			inputValue: "Bearer token123.abc.xyz",
			wantMatch:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := NewPresentHeaderMatcher("test-header")
			gotMatch := matcher.Match(tt.inputValue)
			assert.Equal(t, tt.wantMatch, gotMatch)
		})
	}
}

// =============================================================================
// ExactQueryMatcher Tests
// =============================================================================

func TestNewExactQueryMatcher(t *testing.T) {
	matcher := NewExactQueryMatcher("page", "1")
	assert.NotNil(t, matcher)
	assert.Equal(t, "page", matcher.name)
	assert.Equal(t, "1", matcher.value)
}

func TestExactQueryMatcher_Name(t *testing.T) {
	tests := []struct {
		name      string
		paramName string
		wantName  string
	}{
		{
			name:      "simple parameter name",
			paramName: "page",
			wantName:  "page",
		},
		{
			name:      "parameter name with underscore",
			paramName: "page_size",
			wantName:  "page_size",
		},
		{
			name:      "parameter name with hyphen",
			paramName: "sort-by",
			wantName:  "sort-by",
		},
		{
			name:      "camelCase parameter name",
			paramName: "pageSize",
			wantName:  "pageSize",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := NewExactQueryMatcher(tt.paramName, "value")
			assert.Equal(t, tt.wantName, matcher.Name())
		})
	}
}

func TestExactQueryMatcher_Match(t *testing.T) {
	tests := []struct {
		name         string
		matcherValue string
		inputValue   string
		wantMatch    bool
	}{
		{
			name:         "exact match",
			matcherValue: "1",
			inputValue:   "1",
			wantMatch:    true,
		},
		{
			name:         "non-match different value",
			matcherValue: "1",
			inputValue:   "2",
			wantMatch:    false,
		},
		{
			name:         "string value match",
			matcherValue: "active",
			inputValue:   "active",
			wantMatch:    true,
		},
		{
			name:         "case sensitive non-match",
			matcherValue: "Active",
			inputValue:   "active",
			wantMatch:    false,
		},
		{
			name:         "empty value match",
			matcherValue: "",
			inputValue:   "",
			wantMatch:    true,
		},
		{
			name:         "empty matcher non-match non-empty input",
			matcherValue: "",
			inputValue:   "value",
			wantMatch:    false,
		},
		{
			name:         "complex value match",
			matcherValue: "name,created_at,-updated_at",
			inputValue:   "name,created_at,-updated_at",
			wantMatch:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := NewExactQueryMatcher("param", tt.matcherValue)
			gotMatch := matcher.Match(tt.inputValue)
			assert.Equal(t, tt.wantMatch, gotMatch)
		})
	}
}

// =============================================================================
// RegexQueryMatcher Tests
// =============================================================================

func TestNewRegexQueryMatcher(t *testing.T) {
	tests := []struct {
		name        string
		paramName   string
		pattern     string
		wantErr     bool
		errContains string
	}{
		{
			name:      "valid regex pattern",
			paramName: "page",
			pattern:   "^[0-9]+$",
			wantErr:   false,
		},
		{
			name:      "valid complex regex",
			paramName: "filter",
			pattern:   "^(active|inactive|pending)$",
			wantErr:   false,
		},
		{
			name:        "invalid regex pattern",
			paramName:   "invalid",
			pattern:     "[unclosed",
			wantErr:     true,
			errContains: "error parsing regexp",
		},
		{
			name:      "empty pattern is valid",
			paramName: "empty",
			pattern:   "",
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher, err := NewRegexQueryMatcher(tt.paramName, tt.pattern)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				assert.Nil(t, matcher)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, matcher)
				assert.Equal(t, tt.paramName, matcher.name)
			}
		})
	}
}

func TestRegexQueryMatcher_Name(t *testing.T) {
	matcher, err := NewRegexQueryMatcher("page_size", ".*")
	require.NoError(t, err)
	assert.Equal(t, "page_size", matcher.Name())
}

func TestRegexQueryMatcher_Match(t *testing.T) {
	tests := []struct {
		name       string
		pattern    string
		inputValue string
		wantMatch  bool
	}{
		{
			name:       "numeric pattern match",
			pattern:    "^[0-9]+$",
			inputValue: "123",
			wantMatch:  true,
		},
		{
			name:       "numeric pattern non-match",
			pattern:    "^[0-9]+$",
			inputValue: "abc",
			wantMatch:  false,
		},
		{
			name:       "enum pattern match",
			pattern:    "^(active|inactive|pending)$",
			inputValue: "active",
			wantMatch:  true,
		},
		{
			name:       "enum pattern non-match",
			pattern:    "^(active|inactive|pending)$",
			inputValue: "deleted",
			wantMatch:  false,
		},
		{
			name:       "partial match in string",
			pattern:    "[0-9]+",
			inputValue: "page123",
			wantMatch:  true,
		},
		{
			name:       "uuid pattern match",
			pattern:    "^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$",
			inputValue: "550e8400-e29b-41d4-a716-446655440000",
			wantMatch:  true,
		},
		{
			name:       "empty pattern matches any",
			pattern:    "",
			inputValue: "anything",
			wantMatch:  true,
		},
		{
			name:       "empty pattern matches empty",
			pattern:    "",
			inputValue: "",
			wantMatch:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher, err := NewRegexQueryMatcher("param", tt.pattern)
			require.NoError(t, err)
			gotMatch := matcher.Match(tt.inputValue)
			assert.Equal(t, tt.wantMatch, gotMatch)
		})
	}
}

// =============================================================================
// PresentQueryMatcher Tests
// =============================================================================

func TestNewPresentQueryMatcher(t *testing.T) {
	matcher := NewPresentQueryMatcher("debug")
	assert.NotNil(t, matcher)
	assert.Equal(t, "debug", matcher.name)
}

func TestPresentQueryMatcher_Name(t *testing.T) {
	tests := []struct {
		name      string
		paramName string
		wantName  string
	}{
		{
			name:      "simple parameter name",
			paramName: "debug",
			wantName:  "debug",
		},
		{
			name:      "parameter name with underscore",
			paramName: "include_deleted",
			wantName:  "include_deleted",
		},
		{
			name:      "parameter name preserved as-is",
			paramName: "sortBy",
			wantName:  "sortBy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := NewPresentQueryMatcher(tt.paramName)
			assert.Equal(t, tt.wantName, matcher.Name())
		})
	}
}

func TestPresentQueryMatcher_Match(t *testing.T) {
	tests := []struct {
		name       string
		inputValue string
		wantMatch  bool
	}{
		{
			name:       "always returns true for any value",
			inputValue: "true",
			wantMatch:  true,
		},
		{
			name:       "always returns true for empty value",
			inputValue: "",
			wantMatch:  true,
		},
		{
			name:       "always returns true for numeric value",
			inputValue: "123",
			wantMatch:  true,
		},
		{
			name:       "always returns true for complex value",
			inputValue: "name,created_at,-updated_at",
			wantMatch:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := NewPresentQueryMatcher("param")
			gotMatch := matcher.Match(tt.inputValue)
			assert.Equal(t, tt.wantMatch, gotMatch)
		})
	}
}

// =============================================================================
// HostnameMatcher Tests
// =============================================================================

func TestNewHostnameMatcher(t *testing.T) {
	tests := []struct {
		name        string
		pattern     string
		wantPattern string
		wantRegex   bool
	}{
		{
			name:        "exact hostname",
			pattern:     "api.example.com",
			wantPattern: "api.example.com",
			wantRegex:   true,
		},
		{
			name:        "wildcard all",
			pattern:     "*",
			wantPattern: "*",
			wantRegex:   false,
		},
		{
			name:        "empty pattern",
			pattern:     "",
			wantPattern: "",
			wantRegex:   false,
		},
		{
			name:        "wildcard subdomain",
			pattern:     "*.example.com",
			wantPattern: "*.example.com",
			wantRegex:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := NewHostnameMatcher(tt.pattern)
			assert.NotNil(t, matcher)
			assert.Equal(t, tt.wantPattern, matcher.pattern)
			if tt.wantRegex {
				assert.NotNil(t, matcher.regex)
			} else {
				assert.Nil(t, matcher.regex)
			}
		})
	}
}

func TestHostnameMatcher_Match(t *testing.T) {
	tests := []struct {
		name      string
		pattern   string
		hostname  string
		wantMatch bool
	}{
		{
			name:      "exact hostname match",
			pattern:   "api.example.com",
			hostname:  "api.example.com",
			wantMatch: true,
		},
		{
			name:      "exact hostname non-match",
			pattern:   "api.example.com",
			hostname:  "web.example.com",
			wantMatch: false,
		},
		{
			name:      "wildcard matches all",
			pattern:   "*",
			hostname:  "any.hostname.com",
			wantMatch: true,
		},
		{
			name:      "empty pattern matches all",
			pattern:   "",
			hostname:  "any.hostname.com",
			wantMatch: true,
		},
		{
			name:      "wildcard subdomain match",
			pattern:   "*.example.com",
			hostname:  "api.example.com",
			wantMatch: true,
		},
		{
			name:      "wildcard subdomain match different subdomain",
			pattern:   "*.example.com",
			hostname:  "web.example.com",
			wantMatch: true,
		},
		{
			name:      "wildcard subdomain non-match different domain",
			pattern:   "*.example.com",
			hostname:  "api.other.com",
			wantMatch: false,
		},
		{
			name:      "wildcard subdomain non-match nested subdomain",
			pattern:   "*.example.com",
			hostname:  "api.v1.example.com",
			wantMatch: false,
		},
		{
			name:      "wildcard matches empty hostname",
			pattern:   "*",
			hostname:  "",
			wantMatch: true,
		},
		{
			name:      "empty pattern matches empty hostname",
			pattern:   "",
			hostname:  "",
			wantMatch: true,
		},
		{
			name:      "exact match with port-like pattern",
			pattern:   "api.example.com",
			hostname:  "api.example.com:8080",
			wantMatch: false,
		},
		{
			name:      "case sensitive match",
			pattern:   "API.example.com",
			hostname:  "api.example.com",
			wantMatch: false,
		},
		{
			name:      "wildcard in middle non-match",
			pattern:   "api.*.com",
			hostname:  "api.example.com",
			wantMatch: true,
		},
		{
			name:      "multiple wildcards",
			pattern:   "*.*.com",
			hostname:  "api.example.com",
			wantMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := NewHostnameMatcher(tt.pattern)
			gotMatch := matcher.Match(tt.hostname)
			assert.Equal(t, tt.wantMatch, gotMatch)
		})
	}
}

// Test HostnameMatcher with nil regex (fallback to exact match)
func TestHostnameMatcher_Match_NilRegexFallback(t *testing.T) {
	// Create a matcher with pattern but nil regex (simulating regex compilation failure)
	matcher := &HostnameMatcher{
		pattern: "api.example.com",
		regex:   nil,
	}

	// Should fall back to exact string comparison
	assert.True(t, matcher.Match("api.example.com"))
	assert.False(t, matcher.Match("other.example.com"))
}

// =============================================================================
// Interface Compliance Tests
// =============================================================================

func TestPathMatcherInterface(t *testing.T) {
	var _ PathMatcher = (*ExactPathMatcher)(nil)
	var _ PathMatcher = (*PrefixPathMatcher)(nil)
	var _ PathMatcher = (*RegexPathMatcher)(nil)
}

func TestMethodMatcherInterface(t *testing.T) {
	var _ MethodMatcher = (*SimpleMethodMatcher)(nil)
	var _ MethodMatcher = (*MultiMethodMatcher)(nil)
}

func TestHeaderMatcherInterface(t *testing.T) {
	var _ HeaderMatcher = (*ExactHeaderMatcher)(nil)
	var _ HeaderMatcher = (*RegexHeaderMatcher)(nil)
	var _ HeaderMatcher = (*PresentHeaderMatcher)(nil)
}

func TestQueryMatcherInterface(t *testing.T) {
	var _ QueryMatcher = (*ExactQueryMatcher)(nil)
	var _ QueryMatcher = (*RegexQueryMatcher)(nil)
	var _ QueryMatcher = (*PresentQueryMatcher)(nil)
}
