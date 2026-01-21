// Package transform provides data transformation capabilities for the API Gateway.
package transform

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestNewFieldFilter(t *testing.T) {
	tests := []struct {
		name   string
		logger observability.Logger
	}{
		{
			name:   "with nil logger",
			logger: nil,
		},
		{
			name:   "with nop logger",
			logger: observability.NopLogger(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := NewFieldFilter(tt.logger)
			require.NotNil(t, filter)
		})
	}
}

func TestFieldFilter_FilterAllow(t *testing.T) {
	filter := NewFieldFilter(observability.NopLogger())

	tests := []struct {
		name        string
		data        map[string]interface{}
		allowFields []string
		expected    map[string]interface{}
	}{
		{
			name: "empty allow fields returns original data",
			data: map[string]interface{}{
				"name":  "test",
				"email": "test@example.com",
			},
			allowFields: []string{},
			expected: map[string]interface{}{
				"name":  "test",
				"email": "test@example.com",
			},
		},
		{
			name: "allow specific fields",
			data: map[string]interface{}{
				"name":     "test",
				"email":    "test@example.com",
				"password": "secret",
			},
			allowFields: []string{"name", "email"},
			expected: map[string]interface{}{
				"name":  "test",
				"email": "test@example.com",
			},
		},
		{
			name: "allow nested fields",
			data: map[string]interface{}{
				"user": map[string]interface{}{
					"name":     "test",
					"email":    "test@example.com",
					"password": "secret",
				},
				"other": "data",
			},
			allowFields: []string{"user.name", "user.email"},
			expected: map[string]interface{}{
				"user": map[string]interface{}{
					"name":  "test",
					"email": "test@example.com",
				},
			},
		},
		{
			name: "allow array fields",
			data: map[string]interface{}{
				"items": []interface{}{
					map[string]interface{}{"id": 1, "name": "item1", "secret": "hidden"},
					map[string]interface{}{"id": 2, "name": "item2", "secret": "hidden"},
				},
			},
			allowFields: []string{"items[].id", "items[].name"},
			expected: map[string]interface{}{
				"items": []interface{}{
					map[string]interface{}{"id": 1, "name": "item1"},
					map[string]interface{}{"id": 2, "name": "item2"},
				},
			},
		},
		{
			name: "allow entire nested object",
			data: map[string]interface{}{
				"user": map[string]interface{}{
					"name":  "test",
					"email": "test@example.com",
				},
				"other": "data",
			},
			allowFields: []string{"user"},
			expected: map[string]interface{}{
				"user": map[string]interface{}{
					"name":  "test",
					"email": "test@example.com",
				},
			},
		},
		{
			name: "allow with wildcard",
			data: map[string]interface{}{
				"name":  "test",
				"email": "test@example.com",
				"age":   30,
			},
			allowFields: []string{"*"},
			expected: map[string]interface{}{
				"name":  "test",
				"email": "test@example.com",
				"age":   30,
			},
		},
		{
			name: "allow non-existent field",
			data: map[string]interface{}{
				"name": "test",
			},
			allowFields: []string{"email"},
			expected:    map[string]interface{}{},
		},
		{
			name: "allow primitive array",
			data: map[string]interface{}{
				"tags": []interface{}{"tag1", "tag2", "tag3"},
			},
			allowFields: []string{"tags"},
			expected: map[string]interface{}{
				"tags": []interface{}{"tag1", "tag2", "tag3"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filter.FilterAllow(tt.data, tt.allowFields)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFieldFilter_FilterDeny(t *testing.T) {
	filter := NewFieldFilter(observability.NopLogger())

	tests := []struct {
		name       string
		data       map[string]interface{}
		denyFields []string
		expected   map[string]interface{}
	}{
		{
			name: "empty deny fields returns original data",
			data: map[string]interface{}{
				"name":     "test",
				"password": "secret",
			},
			denyFields: []string{},
			expected: map[string]interface{}{
				"name":     "test",
				"password": "secret",
			},
		},
		{
			name: "deny specific fields",
			data: map[string]interface{}{
				"name":     "test",
				"email":    "test@example.com",
				"password": "secret",
			},
			denyFields: []string{"password"},
			expected: map[string]interface{}{
				"name":  "test",
				"email": "test@example.com",
			},
		},
		{
			name: "deny nested fields",
			data: map[string]interface{}{
				"user": map[string]interface{}{
					"name":     "test",
					"email":    "test@example.com",
					"password": "secret",
				},
			},
			denyFields: []string{"user.password"},
			expected: map[string]interface{}{
				"user": map[string]interface{}{
					"name":  "test",
					"email": "test@example.com",
				},
			},
		},
		{
			name: "deny array fields",
			data: map[string]interface{}{
				"items": []interface{}{
					map[string]interface{}{"id": 1, "name": "item1", "secret": "hidden"},
					map[string]interface{}{"id": 2, "name": "item2", "secret": "hidden"},
				},
			},
			denyFields: []string{"items[].secret"},
			expected: map[string]interface{}{
				"items": []interface{}{
					map[string]interface{}{"id": 1, "name": "item1"},
					map[string]interface{}{"id": 2, "name": "item2"},
				},
			},
		},
		{
			name: "deny entire nested object",
			data: map[string]interface{}{
				"user": map[string]interface{}{
					"name": "test",
				},
				"internal": map[string]interface{}{
					"secret": "hidden",
				},
			},
			denyFields: []string{"internal"},
			expected: map[string]interface{}{
				"user": map[string]interface{}{
					"name": "test",
				},
			},
		},
		{
			name: "deny non-existent field",
			data: map[string]interface{}{
				"name": "test",
			},
			denyFields: []string{"password"},
			expected: map[string]interface{}{
				"name": "test",
			},
		},
		{
			name: "deny multiple fields",
			data: map[string]interface{}{
				"name":     "test",
				"email":    "test@example.com",
				"password": "secret",
				"token":    "abc123",
			},
			denyFields: []string{"password", "token"},
			expected: map[string]interface{}{
				"name":  "test",
				"email": "test@example.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filter.FilterDeny(tt.data, tt.denyFields)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildPathTree(t *testing.T) {
	tests := []struct {
		name     string
		paths    []string
		expected map[string]interface{}
	}{
		{
			name:     "empty paths",
			paths:    []string{},
			expected: map[string]interface{}{},
		},
		{
			name:  "single field",
			paths: []string{"name"},
			expected: map[string]interface{}{
				"name": map[string]interface{}{},
			},
		},
		{
			name:  "nested fields",
			paths: []string{"user.name", "user.email"},
			expected: map[string]interface{}{
				"user": map[string]interface{}{
					"name":  map[string]interface{}{},
					"email": map[string]interface{}{},
				},
			},
		},
		{
			name:  "array notation",
			paths: []string{"items[].id", "items[].name"},
			expected: map[string]interface{}{
				"items": map[string]interface{}{
					"[]": map[string]interface{}{
						"id":   map[string]interface{}{},
						"name": map[string]interface{}{},
					},
				},
			},
		},
		{
			name:  "mixed paths",
			paths: []string{"user.name", "items[].id", "status"},
			expected: map[string]interface{}{
				"user": map[string]interface{}{
					"name": map[string]interface{}{},
				},
				"items": map[string]interface{}{
					"[]": map[string]interface{}{
						"id": map[string]interface{}{},
					},
				},
				"status": map[string]interface{}{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildPathTree(tt.paths)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildPathSet(t *testing.T) {
	tests := []struct {
		name     string
		paths    []string
		expected map[string]bool
	}{
		{
			name:     "empty paths",
			paths:    []string{},
			expected: map[string]bool{},
		},
		{
			name:  "single path",
			paths: []string{"password"},
			expected: map[string]bool{
				"password": true,
			},
		},
		{
			name:  "multiple paths",
			paths: []string{"password", "token", "secret"},
			expected: map[string]bool{
				"password": true,
				"token":    true,
				"secret":   true,
			},
		},
		{
			name:  "nested paths",
			paths: []string{"user.password", "user.token"},
			expected: map[string]bool{
				"user.password": true,
				"user.token":    true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildPathSet(tt.paths)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSplitPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected []string
	}{
		{
			name:     "simple field",
			path:     "name",
			expected: []string{"name"},
		},
		{
			name:     "nested field",
			path:     "user.name",
			expected: []string{"user", "name"},
		},
		{
			name:     "deeply nested field",
			path:     "user.address.city",
			expected: []string{"user", "address", "city"},
		},
		{
			name:     "array notation",
			path:     "items[].id",
			expected: []string{"items", "[]", "id"},
		},
		{
			name:     "array at end",
			path:     "items[]",
			expected: []string{"items", "[]"},
		},
		{
			name:     "nested array",
			path:     "users[].addresses[].city",
			expected: []string{"users", "[]", "addresses", "[]", "city"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := splitPath(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildCurrentPath(t *testing.T) {
	tests := []struct {
		name     string
		prefix   string
		key      string
		expected string
	}{
		{
			name:     "empty prefix",
			prefix:   "",
			key:      "name",
			expected: "name",
		},
		{
			name:     "with prefix",
			prefix:   "user",
			key:      "name",
			expected: "user.name",
		},
		{
			name:     "nested prefix",
			prefix:   "user.address",
			key:      "city",
			expected: "user.address.city",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildCurrentPath(tt.prefix, tt.key)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFieldFilter_FilterAllow_ComplexNesting(t *testing.T) {
	filter := NewFieldFilter(observability.NopLogger())

	data := map[string]interface{}{
		"user": map[string]interface{}{
			"profile": map[string]interface{}{
				"name":  "John",
				"email": "john@example.com",
				"bio":   "Developer",
			},
			"settings": map[string]interface{}{
				"theme":    "dark",
				"language": "en",
			},
		},
		"posts": []interface{}{
			map[string]interface{}{
				"id":      1,
				"title":   "Post 1",
				"content": "Content 1",
				"author": map[string]interface{}{
					"name": "John",
					"id":   123,
				},
			},
		},
	}

	allowFields := []string{"user.profile.name", "user.profile.email", "posts[].id", "posts[].title"}

	result := filter.FilterAllow(data, allowFields)

	// Verify user.profile
	user, ok := result["user"].(map[string]interface{})
	require.True(t, ok)
	profile, ok := user["profile"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "John", profile["name"])
	assert.Equal(t, "john@example.com", profile["email"])
	assert.NotContains(t, profile, "bio")

	// Verify settings is not present
	assert.NotContains(t, user, "settings")

	// Verify posts
	posts, ok := result["posts"].([]interface{})
	require.True(t, ok)
	require.Len(t, posts, 1)
	post, ok := posts[0].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, 1, post["id"])
	assert.Equal(t, "Post 1", post["title"])
	assert.NotContains(t, post, "content")
	assert.NotContains(t, post, "author")
}

func TestFieldFilter_FilterDeny_ComplexNesting(t *testing.T) {
	filter := NewFieldFilter(observability.NopLogger())

	data := map[string]interface{}{
		"user": map[string]interface{}{
			"name":     "John",
			"email":    "john@example.com",
			"password": "secret",
			"token":    "abc123",
		},
		"items": []interface{}{
			map[string]interface{}{
				"id":       1,
				"name":     "Item 1",
				"internal": "hidden",
			},
		},
	}

	denyFields := []string{"user.password", "user.token", "items[].internal"}

	result := filter.FilterDeny(data, denyFields)

	// Verify user
	user, ok := result["user"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "John", user["name"])
	assert.Equal(t, "john@example.com", user["email"])
	assert.NotContains(t, user, "password")
	assert.NotContains(t, user, "token")

	// Verify items
	items, ok := result["items"].([]interface{})
	require.True(t, ok)
	require.Len(t, items, 1)
	item, ok := items[0].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, 1, item["id"])
	assert.Equal(t, "Item 1", item["name"])
	assert.NotContains(t, item, "internal")
}

func TestFieldFilter_FilterAllow_EmptyArrays(t *testing.T) {
	filter := NewFieldFilter(observability.NopLogger())

	data := map[string]interface{}{
		"items": []interface{}{},
		"name":  "test",
	}

	allowFields := []string{"items[].id", "name"}

	result := filter.FilterAllow(data, allowFields)

	assert.Equal(t, "test", result["name"])
	// Empty array should be filtered out since no elements match
}

func TestFieldFilter_FilterDeny_PreservesPrimitiveArrays(t *testing.T) {
	filter := NewFieldFilter(observability.NopLogger())

	data := map[string]interface{}{
		"tags":   []interface{}{"tag1", "tag2", "tag3"},
		"secret": "hidden",
	}

	denyFields := []string{"secret"}

	result := filter.FilterDeny(data, denyFields)

	tags, ok := result["tags"].([]interface{})
	require.True(t, ok)
	assert.Len(t, tags, 3)
	assert.NotContains(t, result, "secret")
}
