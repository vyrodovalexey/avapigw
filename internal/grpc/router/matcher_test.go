package router

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

func TestExactStringMatcher(t *testing.T) {
	t.Parallel()

	matcher := NewExactStringMatcher("test.UserService")

	assert.True(t, matcher.Match("test.UserService"))
	assert.False(t, matcher.Match("test.OrderService"))
	assert.False(t, matcher.Match("test.UserServiceExtra"))
	assert.False(t, matcher.Match(""))
	assert.Equal(t, "exact", matcher.Type())
	assert.Equal(t, "test.UserService", matcher.Pattern())
}

func TestPrefixStringMatcher(t *testing.T) {
	t.Parallel()

	matcher := NewPrefixStringMatcher("test.")

	assert.True(t, matcher.Match("test.UserService"))
	assert.True(t, matcher.Match("test.OrderService"))
	assert.True(t, matcher.Match("test."))
	assert.False(t, matcher.Match("other.Service"))
	assert.False(t, matcher.Match(""))
	assert.Equal(t, "prefix", matcher.Type())
	assert.Equal(t, "test.", matcher.Pattern())
}

func TestRegexStringMatcher(t *testing.T) {
	t.Parallel()

	matcher, err := NewRegexStringMatcher("^test\\..*Service$")
	require.NoError(t, err)

	assert.True(t, matcher.Match("test.UserService"))
	assert.True(t, matcher.Match("test.OrderService"))
	assert.False(t, matcher.Match("test.UserController"))
	assert.False(t, matcher.Match("other.UserService"))
	assert.Equal(t, "regex", matcher.Type())
	assert.Equal(t, "^test\\..*Service$", matcher.Pattern())
}

func TestRegexStringMatcher_InvalidRegex(t *testing.T) {
	t.Parallel()

	_, err := NewRegexStringMatcher("[invalid")
	assert.Error(t, err)
}

func TestRegexStringMatcher_Cache(t *testing.T) {
	t.Parallel()

	// Create two matchers with the same pattern
	matcher1, err := NewRegexStringMatcher("^test\\..*$")
	require.NoError(t, err)

	matcher2, err := NewRegexStringMatcher("^test\\..*$")
	require.NoError(t, err)

	// Both should work correctly
	assert.True(t, matcher1.Match("test.Service"))
	assert.True(t, matcher2.Match("test.Service"))
}

func TestWildcardStringMatcher(t *testing.T) {
	t.Parallel()

	matcher := NewWildcardStringMatcher()

	assert.True(t, matcher.Match("anything"))
	assert.True(t, matcher.Match(""))
	assert.True(t, matcher.Match("test.UserService"))
	assert.Equal(t, "wildcard", matcher.Type())
	assert.Equal(t, "*", matcher.Pattern())
}

func TestNewStringMatcher(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		match        *config.StringMatch
		expectedType string
		shouldMatch  string
		shouldFail   string
	}{
		{
			name:         "nil match returns wildcard",
			match:        nil,
			expectedType: "wildcard",
			shouldMatch:  "anything",
		},
		{
			name:         "exact wildcard returns wildcard",
			match:        &config.StringMatch{Exact: "*"},
			expectedType: "wildcard",
			shouldMatch:  "anything",
		},
		{
			name:         "prefix wildcard returns wildcard",
			match:        &config.StringMatch{Prefix: "*"},
			expectedType: "wildcard",
			shouldMatch:  "anything",
		},
		{
			name:         "exact match",
			match:        &config.StringMatch{Exact: "test.Service"},
			expectedType: "exact",
			shouldMatch:  "test.Service",
			shouldFail:   "other.Service",
		},
		{
			name:         "prefix match",
			match:        &config.StringMatch{Prefix: "test."},
			expectedType: "prefix",
			shouldMatch:  "test.Service",
			shouldFail:   "other.Service",
		},
		{
			name:         "regex match",
			match:        &config.StringMatch{Regex: "^test\\..*"},
			expectedType: "regex",
			shouldMatch:  "test.Service",
			shouldFail:   "other.Service",
		},
		{
			name:         "empty match returns wildcard",
			match:        &config.StringMatch{},
			expectedType: "wildcard",
			shouldMatch:  "anything",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			matcher, err := NewStringMatcher(tt.match)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedType, matcher.Type())
			assert.True(t, matcher.Match(tt.shouldMatch))
			if tt.shouldFail != "" {
				assert.False(t, matcher.Match(tt.shouldFail))
			}
		})
	}
}

func TestNewStringMatcher_InvalidRegex(t *testing.T) {
	t.Parallel()

	_, err := NewStringMatcher(&config.StringMatch{Regex: "[invalid"})
	assert.Error(t, err)
}

func TestExactMetadataMatcher(t *testing.T) {
	t.Parallel()

	matcher := NewExactMetadataMatcher("X-Custom", "value")

	// Should match exact value
	md := metadata.MD{"x-custom": []string{"value"}}
	assert.True(t, matcher.Match(md))

	// Should match with multiple values
	md = metadata.MD{"x-custom": []string{"other", "value"}}
	assert.True(t, matcher.Match(md))

	// Should not match wrong value
	md = metadata.MD{"x-custom": []string{"wrong"}}
	assert.False(t, matcher.Match(md))

	// Should not match missing key
	md = metadata.MD{}
	assert.False(t, matcher.Match(md))

	assert.Equal(t, "x-custom", matcher.Name())
}

func TestPrefixMetadataMatcher(t *testing.T) {
	t.Parallel()

	matcher := NewPrefixMetadataMatcher("X-Custom", "val")

	// Should match prefix
	md := metadata.MD{"x-custom": []string{"value"}}
	assert.True(t, matcher.Match(md))

	// Should match with multiple values
	md = metadata.MD{"x-custom": []string{"other", "value123"}}
	assert.True(t, matcher.Match(md))

	// Should not match wrong prefix
	md = metadata.MD{"x-custom": []string{"wrong"}}
	assert.False(t, matcher.Match(md))

	// Should not match missing key
	md = metadata.MD{}
	assert.False(t, matcher.Match(md))

	assert.Equal(t, "x-custom", matcher.Name())
}

func TestRegexMetadataMatcher(t *testing.T) {
	t.Parallel()

	matcher, err := NewRegexMetadataMatcher("X-Custom", "^v[0-9]+$")
	require.NoError(t, err)

	// Should match regex
	md := metadata.MD{"x-custom": []string{"v123"}}
	assert.True(t, matcher.Match(md))

	// Should match with multiple values
	md = metadata.MD{"x-custom": []string{"wrong", "v456"}}
	assert.True(t, matcher.Match(md))

	// Should not match wrong pattern
	md = metadata.MD{"x-custom": []string{"version1"}}
	assert.False(t, matcher.Match(md))

	// Should not match missing key
	md = metadata.MD{}
	assert.False(t, matcher.Match(md))

	assert.Equal(t, "x-custom", matcher.Name())
}

func TestRegexMetadataMatcher_InvalidRegex(t *testing.T) {
	t.Parallel()

	_, err := NewRegexMetadataMatcher("X-Custom", "[invalid")
	assert.Error(t, err)
}

func TestPresentMetadataMatcher(t *testing.T) {
	t.Parallel()

	matcher := NewPresentMetadataMatcher("X-Custom")

	// Should match when present
	md := metadata.MD{"x-custom": []string{"any-value"}}
	assert.True(t, matcher.Match(md))

	// Should match with empty value
	md = metadata.MD{"x-custom": []string{""}}
	assert.True(t, matcher.Match(md))

	// Should not match when absent
	md = metadata.MD{}
	assert.False(t, matcher.Match(md))

	assert.Equal(t, "x-custom", matcher.Name())
}

func TestAbsentMetadataMatcher(t *testing.T) {
	t.Parallel()

	matcher := NewAbsentMetadataMatcher("X-Custom")

	// Should match when absent
	md := metadata.MD{}
	assert.True(t, matcher.Match(md))

	// Should not match when present
	md = metadata.MD{"x-custom": []string{"value"}}
	assert.False(t, matcher.Match(md))

	assert.Equal(t, "x-custom", matcher.Name())
}

func TestNewMetadataMatcher(t *testing.T) {
	t.Parallel()

	present := true
	absent := true

	tests := []struct {
		name        string
		match       config.MetadataMatch
		shouldMatch metadata.MD
		shouldFail  metadata.MD
	}{
		{
			name:        "present matcher",
			match:       config.MetadataMatch{Name: "x-custom", Present: &present},
			shouldMatch: metadata.MD{"x-custom": []string{"value"}},
			shouldFail:  metadata.MD{},
		},
		{
			name:        "absent matcher",
			match:       config.MetadataMatch{Name: "x-custom", Absent: &absent},
			shouldMatch: metadata.MD{},
			shouldFail:  metadata.MD{"x-custom": []string{"value"}},
		},
		{
			name:        "exact matcher",
			match:       config.MetadataMatch{Name: "x-custom", Exact: "value"},
			shouldMatch: metadata.MD{"x-custom": []string{"value"}},
			shouldFail:  metadata.MD{"x-custom": []string{"wrong"}},
		},
		{
			name:        "prefix matcher",
			match:       config.MetadataMatch{Name: "x-custom", Prefix: "val"},
			shouldMatch: metadata.MD{"x-custom": []string{"value"}},
			shouldFail:  metadata.MD{"x-custom": []string{"wrong"}},
		},
		{
			name:        "regex matcher",
			match:       config.MetadataMatch{Name: "x-custom", Regex: "^v.*"},
			shouldMatch: metadata.MD{"x-custom": []string{"value"}},
			shouldFail:  metadata.MD{"x-custom": []string{"wrong"}},
		},
		{
			name:        "default to present matcher",
			match:       config.MetadataMatch{Name: "x-custom"},
			shouldMatch: metadata.MD{"x-custom": []string{"value"}},
			shouldFail:  metadata.MD{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			matcher, err := NewMetadataMatcher(tt.match)
			require.NoError(t, err)

			assert.True(t, matcher.Match(tt.shouldMatch))
			assert.False(t, matcher.Match(tt.shouldFail))
		})
	}
}

func TestNewMetadataMatcher_InvalidRegex(t *testing.T) {
	t.Parallel()

	_, err := NewMetadataMatcher(config.MetadataMatch{Name: "x-custom", Regex: "[invalid"})
	assert.Error(t, err)
}

func TestParseFullMethod(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		fullMethod      string
		expectedService string
		expectedMethod  string
	}{
		{
			name:            "standard format",
			fullMethod:      "/test.UserService/GetUser",
			expectedService: "test.UserService",
			expectedMethod:  "GetUser",
		},
		{
			name:            "without leading slash",
			fullMethod:      "test.UserService/GetUser",
			expectedService: "test.UserService",
			expectedMethod:  "GetUser",
		},
		{
			name:            "nested package",
			fullMethod:      "/com.example.api.v1.UserService/GetUser",
			expectedService: "com.example.api.v1.UserService",
			expectedMethod:  "GetUser",
		},
		{
			name:            "no method",
			fullMethod:      "/test.UserService",
			expectedService: "test.UserService",
			expectedMethod:  "",
		},
		{
			name:            "empty string",
			fullMethod:      "",
			expectedService: "",
			expectedMethod:  "",
		},
		{
			name:            "only slash",
			fullMethod:      "/",
			expectedService: "",
			expectedMethod:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, method := ParseFullMethod(tt.fullMethod)
			assert.Equal(t, tt.expectedService, service)
			assert.Equal(t, tt.expectedMethod, method)
		})
	}
}

func TestMetadataMatcher_CaseInsensitiveKeys(t *testing.T) {
	t.Parallel()

	// gRPC metadata keys are case-insensitive (converted to lowercase)
	matcher := NewExactMetadataMatcher("X-Custom-Header", "value")

	// Should match lowercase key
	md := metadata.MD{"x-custom-header": []string{"value"}}
	assert.True(t, matcher.Match(md))
}

func BenchmarkExactStringMatcher(b *testing.B) {
	matcher := NewExactStringMatcher("test.UserService")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		matcher.Match("test.UserService")
	}
}

func BenchmarkPrefixStringMatcher(b *testing.B) {
	matcher := NewPrefixStringMatcher("test.")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		matcher.Match("test.UserService")
	}
}

func BenchmarkRegexStringMatcher(b *testing.B) {
	matcher, _ := NewRegexStringMatcher("^test\\..*Service$")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		matcher.Match("test.UserService")
	}
}

func BenchmarkExactMetadataMatcher(b *testing.B) {
	matcher := NewExactMetadataMatcher("x-custom", "value")
	md := metadata.MD{"x-custom": []string{"value"}}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		matcher.Match(md)
	}
}

func BenchmarkParseFullMethod(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParseFullMethod("/test.UserService/GetUser")
	}
}
