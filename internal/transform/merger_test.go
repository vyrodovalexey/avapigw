// Package transform provides data transformation capabilities for the API Gateway.
package transform

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestNewResponseMerger(t *testing.T) {
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
			merger := NewResponseMerger(tt.logger)
			require.NotNil(t, merger)
		})
	}
}

func TestResponseMerger_Merge(t *testing.T) {
	merger := NewResponseMerger(observability.NopLogger())

	tests := []struct {
		name      string
		responses []interface{}
		strategy  string
		expected  interface{}
		expectErr bool
	}{
		{
			name:      "empty responses",
			responses: []interface{}{},
			strategy:  config.MergeStrategyDeep,
			expected:  nil,
		},
		{
			name: "single response",
			responses: []interface{}{
				map[string]interface{}{"name": "test"},
			},
			strategy: config.MergeStrategyDeep,
			expected: map[string]interface{}{"name": "test"},
		},
		{
			name: "deep merge - simple",
			responses: []interface{}{
				map[string]interface{}{"name": "test"},
				map[string]interface{}{"email": "test@example.com"},
			},
			strategy: config.MergeStrategyDeep,
			expected: map[string]interface{}{
				"name":  "test",
				"email": "test@example.com",
			},
		},
		{
			name: "deep merge - nested objects",
			responses: []interface{}{
				map[string]interface{}{
					"user": map[string]interface{}{
						"name": "test",
					},
				},
				map[string]interface{}{
					"user": map[string]interface{}{
						"email": "test@example.com",
					},
				},
			},
			strategy: config.MergeStrategyDeep,
			expected: map[string]interface{}{
				"user": map[string]interface{}{
					"name":  "test",
					"email": "test@example.com",
				},
			},
		},
		{
			name: "deep merge - arrays concatenated",
			responses: []interface{}{
				map[string]interface{}{
					"items": []interface{}{"a", "b"},
				},
				map[string]interface{}{
					"items": []interface{}{"c", "d"},
				},
			},
			strategy: config.MergeStrategyDeep,
			expected: map[string]interface{}{
				"items": []interface{}{"a", "b", "c", "d"},
			},
		},
		{
			name: "shallow merge - nested objects replaced",
			responses: []interface{}{
				map[string]interface{}{
					"user": map[string]interface{}{
						"name":  "test",
						"email": "old@example.com",
					},
				},
				map[string]interface{}{
					"user": map[string]interface{}{
						"email": "new@example.com",
					},
				},
			},
			strategy: config.MergeStrategyShallow,
			expected: map[string]interface{}{
				"user": map[string]interface{}{
					"email": "new@example.com",
				},
			},
		},
		{
			name: "replace strategy - returns last",
			responses: []interface{}{
				map[string]interface{}{"name": "first"},
				map[string]interface{}{"name": "second"},
				map[string]interface{}{"name": "third"},
			},
			strategy: config.MergeStrategyReplace,
			expected: map[string]interface{}{"name": "third"},
		},
		{
			name: "replace strategy - skips nil",
			responses: []interface{}{
				map[string]interface{}{"name": "first"},
				nil,
				map[string]interface{}{"name": "third"},
			},
			strategy: config.MergeStrategyReplace,
			expected: map[string]interface{}{"name": "third"},
		},
		{
			name: "default strategy is deep",
			responses: []interface{}{
				map[string]interface{}{"a": 1},
				map[string]interface{}{"b": 2},
			},
			strategy: "",
			expected: map[string]interface{}{
				"a": 1,
				"b": 2,
			},
		},
		{
			name: "unknown strategy returns error",
			responses: []interface{}{
				map[string]interface{}{"name": "test"},
			},
			strategy:  "invalid",
			expectErr: true,
		},
		{
			name: "merge with nil response",
			responses: []interface{}{
				map[string]interface{}{"name": "test"},
				nil,
			},
			strategy: config.MergeStrategyDeep,
			expected: map[string]interface{}{"name": "test"},
		},
		{
			name: "merge arrays at root",
			responses: []interface{}{
				[]interface{}{"a", "b"},
				[]interface{}{"c", "d"},
			},
			strategy: config.MergeStrategyDeep,
			expected: []interface{}{"a", "b", "c", "d"},
		},
		{
			name: "merge different types - source wins",
			responses: []interface{}{
				map[string]interface{}{"value": "string"},
				map[string]interface{}{"value": 123},
			},
			strategy: config.MergeStrategyDeep,
			expected: map[string]interface{}{"value": 123},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := merger.Merge(tt.responses, tt.strategy)

			if tt.expectErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestResponseMerger_DeepMerge_Complex(t *testing.T) {
	merger := NewResponseMerger(observability.NopLogger())

	responses := []interface{}{
		map[string]interface{}{
			"user": map[string]interface{}{
				"name": "John",
				"profile": map[string]interface{}{
					"bio": "Developer",
				},
			},
			"items": []interface{}{
				map[string]interface{}{"id": 1},
			},
		},
		map[string]interface{}{
			"user": map[string]interface{}{
				"email": "john@example.com",
				"profile": map[string]interface{}{
					"avatar": "avatar.png",
				},
			},
			"items": []interface{}{
				map[string]interface{}{"id": 2},
			},
		},
		map[string]interface{}{
			"metadata": map[string]interface{}{
				"version": "1.0",
			},
		},
	}

	result, err := merger.Merge(responses, config.MergeStrategyDeep)
	require.NoError(t, err)

	resultMap, ok := result.(map[string]interface{})
	require.True(t, ok)

	// Verify user
	user, ok := resultMap["user"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "John", user["name"])
	assert.Equal(t, "john@example.com", user["email"])

	// Verify nested profile
	profile, ok := user["profile"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "Developer", profile["bio"])
	assert.Equal(t, "avatar.png", profile["avatar"])

	// Verify items array concatenation
	items, ok := resultMap["items"].([]interface{})
	require.True(t, ok)
	assert.Len(t, items, 2)

	// Verify metadata
	metadata, ok := resultMap["metadata"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "1.0", metadata["version"])
}

func TestResponseMerger_ShallowMerge(t *testing.T) {
	merger := NewResponseMerger(observability.NopLogger())

	responses := []interface{}{
		map[string]interface{}{
			"user": map[string]interface{}{
				"name":  "John",
				"email": "john@example.com",
			},
			"count": 10,
		},
		map[string]interface{}{
			"user": map[string]interface{}{
				"name": "Jane",
			},
			"status": "active",
		},
	}

	result, err := merger.Merge(responses, config.MergeStrategyShallow)
	require.NoError(t, err)

	resultMap, ok := result.(map[string]interface{})
	require.True(t, ok)

	// User should be replaced entirely (shallow merge)
	user, ok := resultMap["user"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "Jane", user["name"])
	assert.NotContains(t, user, "email") // email should not be present

	// Other fields should be merged
	assert.Equal(t, 10, resultMap["count"])
	assert.Equal(t, "active", resultMap["status"])
}

func TestResponseMerger_ReplaceMerge_AllNil(t *testing.T) {
	merger := NewResponseMerger(observability.NopLogger())

	responses := []interface{}{nil, nil, nil}

	result, err := merger.Merge(responses, config.MergeStrategyReplace)
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestMergeWithConfig(t *testing.T) {
	tests := []struct {
		name      string
		responses []interface{}
		cfg       *config.ResponseTransformConfig
		expected  interface{}
		expectErr bool
	}{
		{
			name:      "nil config returns error",
			responses: []interface{}{map[string]interface{}{"name": "test"}},
			cfg:       nil,
			expectErr: true,
		},
		{
			name: "with deep merge strategy",
			responses: []interface{}{
				map[string]interface{}{"a": 1},
				map[string]interface{}{"b": 2},
			},
			cfg: &config.ResponseTransformConfig{
				MergeStrategy: config.MergeStrategyDeep,
			},
			expected: map[string]interface{}{
				"a": 1,
				"b": 2,
			},
		},
		{
			name: "with shallow merge strategy",
			responses: []interface{}{
				map[string]interface{}{"a": 1},
				map[string]interface{}{"b": 2},
			},
			cfg: &config.ResponseTransformConfig{
				MergeStrategy: config.MergeStrategyShallow,
			},
			expected: map[string]interface{}{
				"a": 1,
				"b": 2,
			},
		},
		{
			name: "with replace merge strategy",
			responses: []interface{}{
				map[string]interface{}{"a": 1},
				map[string]interface{}{"b": 2},
			},
			cfg: &config.ResponseTransformConfig{
				MergeStrategy: config.MergeStrategyReplace,
			},
			expected: map[string]interface{}{
				"b": 2,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := MergeWithConfig(tt.responses, tt.cfg, observability.NopLogger())

			if tt.expectErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestResponseMerger_DoesNotModifyOriginal(t *testing.T) {
	merger := NewResponseMerger(observability.NopLogger())

	original1 := map[string]interface{}{
		"name": "test1",
		"nested": map[string]interface{}{
			"key": "value1",
		},
	}

	original2 := map[string]interface{}{
		"email": "test@example.com",
		"nested": map[string]interface{}{
			"other": "value2",
		},
	}

	// Make copies to compare later
	copy1 := map[string]interface{}{
		"name": "test1",
		"nested": map[string]interface{}{
			"key": "value1",
		},
	}

	copy2 := map[string]interface{}{
		"email": "test@example.com",
		"nested": map[string]interface{}{
			"other": "value2",
		},
	}

	responses := []interface{}{original1, original2}

	_, err := merger.Merge(responses, config.MergeStrategyDeep)
	require.NoError(t, err)

	// Originals should be unchanged
	assert.Equal(t, copy1["name"], original1["name"])
	assert.Equal(t, copy2["email"], original2["email"])
}

func TestResponseMerger_MergeArraysOfObjects(t *testing.T) {
	merger := NewResponseMerger(observability.NopLogger())

	responses := []interface{}{
		map[string]interface{}{
			"items": []interface{}{
				map[string]interface{}{"id": 1, "name": "item1"},
			},
		},
		map[string]interface{}{
			"items": []interface{}{
				map[string]interface{}{"id": 2, "name": "item2"},
			},
		},
	}

	result, err := merger.Merge(responses, config.MergeStrategyDeep)
	require.NoError(t, err)

	resultMap, ok := result.(map[string]interface{})
	require.True(t, ok)

	items, ok := resultMap["items"].([]interface{})
	require.True(t, ok)
	assert.Len(t, items, 2)

	// Verify first item
	item1, ok := items[0].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, 1, item1["id"])
	assert.Equal(t, "item1", item1["name"])

	// Verify second item
	item2, ok := items[1].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, 2, item2["id"])
	assert.Equal(t, "item2", item2["name"])
}

func TestResponseMerger_MergePrimitives(t *testing.T) {
	merger := NewResponseMerger(observability.NopLogger())

	tests := []struct {
		name      string
		responses []interface{}
		expected  interface{}
	}{
		{
			name:      "merge strings - last wins",
			responses: []interface{}{"first", "second"},
			expected:  "second",
		},
		{
			name:      "merge numbers - last wins",
			responses: []interface{}{1, 2, 3},
			expected:  3,
		},
		{
			name:      "merge mixed - last wins",
			responses: []interface{}{"string", 123},
			expected:  123,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := merger.Merge(tt.responses, config.MergeStrategyDeep)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}
