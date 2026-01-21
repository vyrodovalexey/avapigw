package router

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

func TestExactMatcher(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		pattern  string
		path     string
		expected bool
	}{
		{
			name:     "exact match",
			pattern:  "/api/v1/users",
			path:     "/api/v1/users",
			expected: true,
		},
		{
			name:     "no match different path",
			pattern:  "/api/v1/users",
			path:     "/api/v1/orders",
			expected: false,
		},
		{
			name:     "no match with trailing slash",
			pattern:  "/api/v1/users",
			path:     "/api/v1/users/",
			expected: false,
		},
		{
			name:     "no match prefix",
			pattern:  "/api/v1/users",
			path:     "/api/v1/users/123",
			expected: false,
		},
		{
			name:     "root path",
			pattern:  "/",
			path:     "/",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			matcher := NewExactMatcher(tt.pattern)
			matched, params := matcher.Match(tt.path)
			assert.Equal(t, tt.expected, matched)
			assert.Nil(t, params)
			assert.Equal(t, "exact", matcher.Type())
			assert.Equal(t, tt.pattern, matcher.Pattern())
		})
	}
}

func TestPrefixMatcher(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		pattern  string
		path     string
		expected bool
	}{
		{
			name:     "exact prefix match",
			pattern:  "/api/v1",
			path:     "/api/v1",
			expected: true,
		},
		{
			name:     "prefix with subpath",
			pattern:  "/api/v1",
			path:     "/api/v1/users",
			expected: true,
		},
		{
			name:     "prefix with trailing slash",
			pattern:  "/api/",
			path:     "/api/v1",
			expected: true,
		},
		{
			name:     "no match different prefix",
			pattern:  "/api/v1",
			path:     "/api/v2/users",
			expected: false,
		},
		{
			name:     "no match partial word",
			pattern:  "/api",
			path:     "/apikey",
			expected: false,
		},
		{
			name:     "root prefix",
			pattern:  "/",
			path:     "/anything",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			matcher := NewPrefixMatcher(tt.pattern)
			matched, params := matcher.Match(tt.path)
			assert.Equal(t, tt.expected, matched)
			assert.Nil(t, params)
			assert.Equal(t, "prefix", matcher.Type())
			assert.Equal(t, tt.pattern, matcher.Pattern())
		})
	}
}

func TestRegexMatcher(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		pattern        string
		path           string
		expected       bool
		expectedParams map[string]string
	}{
		{
			name:     "simple regex match",
			pattern:  "^/api/.*",
			path:     "/api/v1/users",
			expected: true,
		},
		{
			name:     "no match",
			pattern:  "^/api/.*",
			path:     "/other/path",
			expected: false,
		},
		{
			name:           "named group",
			pattern:        `^/users/(?P<id>\d+)$`,
			path:           "/users/123",
			expected:       true,
			expectedParams: map[string]string{"id": "123"},
		},
		{
			name:           "multiple named groups",
			pattern:        `^/users/(?P<userId>\d+)/orders/(?P<orderId>\d+)$`,
			path:           "/users/123/orders/456",
			expected:       true,
			expectedParams: map[string]string{"userId": "123", "orderId": "456"},
		},
		{
			name:     "no match named group",
			pattern:  `^/users/(?P<id>\d+)$`,
			path:     "/users/abc",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			matcher, err := NewRegexMatcher(tt.pattern)
			require.NoError(t, err)

			matched, params := matcher.Match(tt.path)
			assert.Equal(t, tt.expected, matched)
			if tt.expectedParams != nil {
				assert.Equal(t, tt.expectedParams, params)
			}
			assert.Equal(t, "regex", matcher.Type())
			assert.Equal(t, tt.pattern, matcher.Pattern())
		})
	}
}

func TestRegexMatcher_InvalidPattern(t *testing.T) {
	t.Parallel()

	_, err := NewRegexMatcher("[invalid")
	assert.Error(t, err)
}

func TestRegexMatcher_Cache(t *testing.T) {
	t.Parallel()

	pattern := "^/test/.*"

	// Create first matcher
	matcher1, err := NewRegexMatcher(pattern)
	require.NoError(t, err)

	// Create second matcher with same pattern (should use cache)
	matcher2, err := NewRegexMatcher(pattern)
	require.NoError(t, err)

	// Both should work correctly
	matched1, _ := matcher1.Match("/test/path")
	matched2, _ := matcher2.Match("/test/path")
	assert.True(t, matched1)
	assert.True(t, matched2)
}

func TestParameterMatcher(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		pattern        string
		path           string
		expected       bool
		expectedParams map[string]string
	}{
		{
			name:           "single parameter",
			pattern:        "/users/{id}",
			path:           "/users/123",
			expected:       true,
			expectedParams: map[string]string{"id": "123"},
		},
		{
			name:           "multiple parameters",
			pattern:        "/users/{userId}/orders/{orderId}",
			path:           "/users/123/orders/456",
			expected:       true,
			expectedParams: map[string]string{"userId": "123", "orderId": "456"},
		},
		{
			name:           "parameter with static prefix",
			pattern:        "/api/v1/users/{id}",
			path:           "/api/v1/users/abc",
			expected:       true,
			expectedParams: map[string]string{"id": "abc"},
		},
		{
			name:     "no match wrong path",
			pattern:  "/users/{id}",
			path:     "/orders/123",
			expected: false,
		},
		{
			name:     "no match extra segment",
			pattern:  "/users/{id}",
			path:     "/users/123/extra",
			expected: false,
		},
		{
			name:     "no match missing segment",
			pattern:  "/users/{id}/orders",
			path:     "/users/123",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			matcher, err := NewParameterMatcher(tt.pattern)
			require.NoError(t, err)

			matched, params := matcher.Match(tt.path)
			assert.Equal(t, tt.expected, matched)
			if tt.expectedParams != nil {
				assert.Equal(t, tt.expectedParams, params)
			}
			assert.Equal(t, "parameter", matcher.Type())
			assert.Equal(t, tt.pattern, matcher.Pattern())
		})
	}
}

func TestWildcardMatcher(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		pattern  string
		path     string
		expected bool
	}{
		{
			name:     "single wildcard",
			pattern:  "/api/*/users",
			path:     "/api/v1/users",
			expected: true,
		},
		{
			name:     "single wildcard no match",
			pattern:  "/api/*/users",
			path:     "/api/v1/v2/users",
			expected: false,
		},
		{
			name:     "double wildcard",
			pattern:  "/api/**",
			path:     "/api/v1/users/123",
			expected: true,
		},
		{
			name:     "double wildcard at start",
			pattern:  "**/users",
			path:     "/api/v1/users",
			expected: true,
		},
		{
			name:     "question mark wildcard",
			pattern:  "/api/v?/users",
			path:     "/api/v1/users",
			expected: true,
		},
		{
			name:     "question mark no match",
			pattern:  "/api/v?/users",
			path:     "/api/v10/users",
			expected: false,
		},
		{
			name:     "mixed wildcards",
			pattern:  "/api/*/users/**",
			path:     "/api/v1/users/123/orders",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			matcher, err := NewWildcardMatcher(tt.pattern)
			require.NoError(t, err)

			matched, params := matcher.Match(tt.path)
			assert.Equal(t, tt.expected, matched)
			assert.Nil(t, params)
			assert.Equal(t, "wildcard", matcher.Type())
			assert.Equal(t, tt.pattern, matcher.Pattern())
		})
	}
}

func TestMethodMatcher(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		methods  []string
		method   string
		expected bool
	}{
		{
			name:     "single method match",
			methods:  []string{"GET"},
			method:   "GET",
			expected: true,
		},
		{
			name:     "multiple methods match",
			methods:  []string{"GET", "POST"},
			method:   "POST",
			expected: true,
		},
		{
			name:     "no match",
			methods:  []string{"GET", "POST"},
			method:   "DELETE",
			expected: false,
		},
		{
			name:     "wildcard matches all",
			methods:  []string{"*"},
			method:   "DELETE",
			expected: true,
		},
		{
			name:     "HEAD matches GET",
			methods:  []string{"GET"},
			method:   "HEAD",
			expected: true,
		},
		{
			name:     "case insensitive",
			methods:  []string{"get"},
			method:   "GET",
			expected: true,
		},
		{
			name:     "lowercase input",
			methods:  []string{"GET"},
			method:   "get",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			matcher := NewMethodMatcher(tt.methods)
			assert.Equal(t, tt.expected, matcher.Match(tt.method))
		})
	}
}

func TestHeaderMatcher(t *testing.T) {
	t.Parallel()

	boolPtr := func(b bool) *bool { return &b }

	tests := []struct {
		name     string
		config   config.HeaderMatch
		headers  http.Header
		expected bool
	}{
		{
			name:     "exact match",
			config:   config.HeaderMatch{Name: "X-Custom", Exact: "value"},
			headers:  http.Header{"X-Custom": []string{"value"}},
			expected: true,
		},
		{
			name:     "exact no match",
			config:   config.HeaderMatch{Name: "X-Custom", Exact: "value"},
			headers:  http.Header{"X-Custom": []string{"other"}},
			expected: false,
		},
		{
			name:     "prefix match",
			config:   config.HeaderMatch{Name: "X-Custom", Prefix: "val"},
			headers:  http.Header{"X-Custom": []string{"value"}},
			expected: true,
		},
		{
			name:     "prefix no match",
			config:   config.HeaderMatch{Name: "X-Custom", Prefix: "other"},
			headers:  http.Header{"X-Custom": []string{"value"}},
			expected: false,
		},
		{
			name:     "regex match",
			config:   config.HeaderMatch{Name: "X-Custom", Regex: "^val.*"},
			headers:  http.Header{"X-Custom": []string{"value"}},
			expected: true,
		},
		{
			name:     "regex no match",
			config:   config.HeaderMatch{Name: "X-Custom", Regex: "^other.*"},
			headers:  http.Header{"X-Custom": []string{"value"}},
			expected: false,
		},
		{
			name:     "present true - header exists",
			config:   config.HeaderMatch{Name: "X-Custom", Present: boolPtr(true)},
			headers:  http.Header{"X-Custom": []string{"value"}},
			expected: true,
		},
		{
			name:     "present true - header missing",
			config:   config.HeaderMatch{Name: "X-Custom", Present: boolPtr(true)},
			headers:  http.Header{},
			expected: false,
		},
		{
			name:     "present false - header missing",
			config:   config.HeaderMatch{Name: "X-Custom", Present: boolPtr(false)},
			headers:  http.Header{},
			expected: true,
		},
		{
			name:     "present false - header exists",
			config:   config.HeaderMatch{Name: "X-Custom", Present: boolPtr(false)},
			headers:  http.Header{"X-Custom": []string{"value"}},
			expected: false,
		},
		{
			name:     "absent true - header missing",
			config:   config.HeaderMatch{Name: "X-Custom", Absent: boolPtr(true)},
			headers:  http.Header{},
			expected: true,
		},
		{
			name:     "absent true - header exists",
			config:   config.HeaderMatch{Name: "X-Custom", Absent: boolPtr(true)},
			headers:  http.Header{"X-Custom": []string{"value"}},
			expected: false,
		},
		{
			name:     "absent false - header exists",
			config:   config.HeaderMatch{Name: "X-Custom", Absent: boolPtr(false)},
			headers:  http.Header{"X-Custom": []string{"value"}},
			expected: true,
		},
		{
			name:     "absent false - header missing",
			config:   config.HeaderMatch{Name: "X-Custom", Absent: boolPtr(false)},
			headers:  http.Header{},
			expected: false,
		},
		{
			name:     "header required but missing",
			config:   config.HeaderMatch{Name: "X-Custom"},
			headers:  http.Header{},
			expected: false,
		},
		{
			name:     "header exists no conditions",
			config:   config.HeaderMatch{Name: "X-Custom"},
			headers:  http.Header{"X-Custom": []string{"value"}},
			expected: true,
		},
		{
			name:     "case insensitive header name",
			config:   config.HeaderMatch{Name: "x-custom", Exact: "value"},
			headers:  http.Header{"X-Custom": []string{"value"}},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			matcher, err := NewHeaderMatcher(tt.config)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, matcher.Match(tt.headers))
		})
	}
}

func TestHeaderMatcher_InvalidRegex(t *testing.T) {
	t.Parallel()

	_, err := NewHeaderMatcher(config.HeaderMatch{Name: "X-Custom", Regex: "[invalid"})
	assert.Error(t, err)
}

func TestQueryParamMatcher(t *testing.T) {
	t.Parallel()

	boolPtr := func(b bool) *bool { return &b }

	tests := []struct {
		name     string
		config   config.QueryParamMatch
		query    url.Values
		expected bool
	}{
		{
			name:     "exact match",
			config:   config.QueryParamMatch{Name: "id", Exact: "123"},
			query:    url.Values{"id": []string{"123"}},
			expected: true,
		},
		{
			name:     "exact no match",
			config:   config.QueryParamMatch{Name: "id", Exact: "123"},
			query:    url.Values{"id": []string{"456"}},
			expected: false,
		},
		{
			name:     "regex match",
			config:   config.QueryParamMatch{Name: "id", Regex: `^\d+$`},
			query:    url.Values{"id": []string{"123"}},
			expected: true,
		},
		{
			name:     "regex no match",
			config:   config.QueryParamMatch{Name: "id", Regex: `^\d+$`},
			query:    url.Values{"id": []string{"abc"}},
			expected: false,
		},
		{
			name:     "present true - param exists",
			config:   config.QueryParamMatch{Name: "id", Present: boolPtr(true)},
			query:    url.Values{"id": []string{"123"}},
			expected: true,
		},
		{
			name:     "present true - param missing",
			config:   config.QueryParamMatch{Name: "id", Present: boolPtr(true)},
			query:    url.Values{},
			expected: false,
		},
		{
			name:     "present false - param missing",
			config:   config.QueryParamMatch{Name: "id", Present: boolPtr(false)},
			query:    url.Values{},
			expected: true,
		},
		{
			name:     "present false - param exists",
			config:   config.QueryParamMatch{Name: "id", Present: boolPtr(false)},
			query:    url.Values{"id": []string{"123"}},
			expected: false,
		},
		{
			name:     "param required but missing",
			config:   config.QueryParamMatch{Name: "id"},
			query:    url.Values{},
			expected: false,
		},
		{
			name:     "param exists no conditions",
			config:   config.QueryParamMatch{Name: "id"},
			query:    url.Values{"id": []string{"123"}},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			matcher, err := NewQueryParamMatcher(tt.config)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, matcher.Match(tt.query))
		})
	}
}

func TestQueryParamMatcher_InvalidRegex(t *testing.T) {
	t.Parallel()

	_, err := NewQueryParamMatcher(config.QueryParamMatch{Name: "id", Regex: "[invalid"})
	assert.Error(t, err)
}

func TestCreatePathMatcher(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		uri          *config.URIMatch
		expectedType string
		expectNil    bool
	}{
		{
			name:         "exact match",
			uri:          &config.URIMatch{Exact: "/api/v1"},
			expectedType: "exact",
		},
		{
			name:         "prefix match",
			uri:          &config.URIMatch{Prefix: "/api/"},
			expectedType: "prefix",
		},
		{
			name:         "regex match",
			uri:          &config.URIMatch{Regex: "^/api/.*"},
			expectedType: "regex",
		},
		{
			name:      "nil uri",
			uri:       nil,
			expectNil: true,
		},
		{
			name:      "empty uri",
			uri:       &config.URIMatch{},
			expectNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			matcher, err := CreatePathMatcher(tt.uri)
			require.NoError(t, err)
			if tt.expectNil {
				assert.Nil(t, matcher)
			} else {
				assert.NotNil(t, matcher)
				assert.Equal(t, tt.expectedType, matcher.Type())
			}
		})
	}
}

func TestHasPathParameters(t *testing.T) {
	t.Parallel()

	tests := []struct {
		path     string
		expected bool
	}{
		{"/users/{id}", true},
		{"/users/{id}/orders/{orderId}", true},
		{"/users/123", false},
		{"/api/v1", false},
		{"/{}", true},
		{"/users/{", false},
		{"/users/}", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, HasPathParameters(tt.path))
		})
	}
}

func TestHasWildcards(t *testing.T) {
	t.Parallel()

	tests := []struct {
		path     string
		expected bool
	}{
		{"/api/*", true},
		{"/api/**", true},
		{"/api/v1", false},
		{"/users/{id}", false},
		{"*", true},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, HasWildcards(tt.path))
		})
	}
}

func TestParsePathPattern(t *testing.T) {
	t.Parallel()

	tests := []struct {
		pattern  string
		expected []segment
	}{
		{
			pattern: "/users/{id}",
			expected: []segment{
				{value: "users", isParam: false},
				{value: "{id}", isParam: true, paramName: "id"},
			},
		},
		{
			pattern: "/api/v1/users",
			expected: []segment{
				{value: "api", isParam: false},
				{value: "v1", isParam: false},
				{value: "users", isParam: false},
			},
		},
		{
			pattern: "/{a}/{b}/{c}",
			expected: []segment{
				{value: "{a}", isParam: true, paramName: "a"},
				{value: "{b}", isParam: true, paramName: "b"},
				{value: "{c}", isParam: true, paramName: "c"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			t.Parallel()
			result := parsePathPattern(tt.pattern)
			assert.Equal(t, len(tt.expected), len(result))
			for i, seg := range result {
				assert.Equal(t, tt.expected[i].value, seg.value)
				assert.Equal(t, tt.expected[i].isParam, seg.isParam)
				assert.Equal(t, tt.expected[i].paramName, seg.paramName)
			}
		})
	}
}

func TestWildcardToRegex(t *testing.T) {
	t.Parallel()

	tests := []struct {
		pattern  string
		expected string
	}{
		{"/api/*", `^/api/[^/]*$`},
		{"/api/**", `^/api/.*$`},
		{"/api/?", `^/api/[^/]$`},
		{"/api/v1", `^/api/v1$`},
	}

	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			t.Parallel()
			result := wildcardToRegex(tt.pattern)
			assert.Equal(t, tt.expected, result)
		})
	}
}
