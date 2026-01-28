// Package transform provides data transformation capabilities for the API Gateway.
package transform

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestNewResponseTransformer(t *testing.T) {
	tests := []struct {
		name   string
		logger observability.Logger
		opts   []ResponseTransformerOption
	}{
		{
			name:   "with nil logger",
			logger: nil,
		},
		{
			name:   "with nop logger",
			logger: observability.NopLogger(),
		},
		{
			name:   "with custom field filter",
			logger: observability.NopLogger(),
			opts:   []ResponseTransformerOption{WithFieldFilter(NewFieldFilter(nil))},
		},
		{
			name:   "with custom field mapper",
			logger: observability.NopLogger(),
			opts:   []ResponseTransformerOption{WithFieldMapper(NewFieldMapper(nil))},
		},
		{
			name:   "with custom template engine",
			logger: observability.NopLogger(),
			opts:   []ResponseTransformerOption{WithTemplateEngine(NewTemplateEngine(nil))},
		},
		{
			name:   "with custom merger",
			logger: observability.NopLogger(),
			opts:   []ResponseTransformerOption{WithMerger(NewResponseMerger(nil))},
		},
		{
			name:   "with response logger",
			logger: observability.NopLogger(),
			opts:   []ResponseTransformerOption{WithResponseLogger(observability.NopLogger())},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transformer := NewResponseTransformer(tt.logger, tt.opts...)
			require.NotNil(t, transformer)
		})
	}
}

func TestResponseTransformer_Transform(t *testing.T) {
	transformer := NewResponseTransformer(observability.NopLogger())

	data := map[string]interface{}{"name": "test"}
	result, err := transformer.Transform(context.Background(), data)

	require.NoError(t, err)
	assert.Equal(t, data, result)
}

func TestResponseTransformer_TransformResponse(t *testing.T) {
	transformer := NewResponseTransformer(observability.NopLogger())

	tests := []struct {
		name      string
		response  interface{}
		cfg       *config.ResponseTransformConfig
		expected  interface{}
		expectErr bool
	}{
		{
			name:     "nil config returns response",
			response: map[string]interface{}{"name": "test"},
			cfg:      nil,
			expected: map[string]interface{}{"name": "test"},
		},
		{
			name:     "nil response returns nil",
			response: nil,
			cfg:      &config.ResponseTransformConfig{},
			expected: nil,
		},
		{
			name: "allow fields filtering",
			response: map[string]interface{}{
				"name":     "test",
				"email":    "test@example.com",
				"password": "secret",
			},
			cfg: &config.ResponseTransformConfig{
				AllowFields: []string{"name", "email"},
			},
			expected: map[string]interface{}{
				"name":  "test",
				"email": "test@example.com",
			},
		},
		{
			name: "deny fields filtering",
			response: map[string]interface{}{
				"name":     "test",
				"email":    "test@example.com",
				"password": "secret",
			},
			cfg: &config.ResponseTransformConfig{
				DenyFields: []string{"password"},
			},
			expected: map[string]interface{}{
				"name":  "test",
				"email": "test@example.com",
			},
		},
		{
			name: "field mappings",
			response: map[string]interface{}{
				"old_name": "test",
			},
			cfg: &config.ResponseTransformConfig{
				FieldMappings: []config.FieldMapping{
					{Source: "old_name", Target: "new_name"},
				},
			},
			expected: map[string]interface{}{
				"new_name": "test",
			},
		},
		{
			name: "group fields",
			response: map[string]interface{}{
				"name":  "test",
				"email": "test@example.com",
				"phone": "123-456-7890",
			},
			cfg: &config.ResponseTransformConfig{
				GroupFields: []config.FieldGroup{
					{Name: "contact", Fields: []string{"email", "phone"}},
				},
			},
			expected: map[string]interface{}{
				"name": "test",
				"contact": map[string]interface{}{
					"email": "test@example.com",
					"phone": "123-456-7890",
				},
			},
		},
		{
			name: "flatten fields",
			response: map[string]interface{}{
				"name": "test",
				"metadata": map[string]interface{}{
					"created": "2024-01-01",
					"updated": "2024-01-02",
				},
			},
			cfg: &config.ResponseTransformConfig{
				FlattenFields: []string{"metadata"},
			},
			expected: map[string]interface{}{
				"name":    "test",
				"created": "2024-01-01",
				"updated": "2024-01-02",
			},
		},
		{
			name: "template transformation",
			response: map[string]interface{}{
				"name": "test",
			},
			cfg: &config.ResponseTransformConfig{
				Template: `{"greeting": "Hello, {{.name}}!"}`,
			},
			expected: map[string]interface{}{
				"greeting": "Hello, test!",
			},
		},
		{
			name:     "non-map response returns as-is",
			response: "string response",
			cfg: &config.ResponseTransformConfig{
				AllowFields: []string{"name"},
			},
			expected: "string response",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := transformer.TransformResponse(context.Background(), tt.response, tt.cfg)

			if tt.expectErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestResponseTransformer_TransformArray(t *testing.T) {
	transformer := NewResponseTransformer(observability.NopLogger())

	response := []interface{}{
		map[string]interface{}{"id": 1, "name": "item1", "secret": "hidden"},
		map[string]interface{}{"id": 2, "name": "item2", "secret": "hidden"},
	}

	cfg := &config.ResponseTransformConfig{
		AllowFields: []string{"id", "name"},
	}

	result, err := transformer.TransformResponse(context.Background(), response, cfg)
	require.NoError(t, err)

	resultArr, ok := result.([]interface{})
	require.True(t, ok)
	require.Len(t, resultArr, 2)

	// Verify first item
	item1, ok := resultArr[0].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, 1, item1["id"])
	assert.Equal(t, "item1", item1["name"])
	assert.NotContains(t, item1, "secret")

	// Verify second item
	item2, ok := resultArr[1].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, 2, item2["id"])
	assert.Equal(t, "item2", item2["name"])
	assert.NotContains(t, item2, "secret")
}

func TestResponseTransformer_ArrayOperations(t *testing.T) {
	transformer := NewResponseTransformer(observability.NopLogger())

	tests := []struct {
		name      string
		response  interface{}
		cfg       *config.ResponseTransformConfig
		checkFunc func(t *testing.T, result interface{})
	}{
		{
			name: "limit array",
			response: map[string]interface{}{
				"items": []interface{}{"a", "b", "c", "d", "e"},
			},
			cfg: &config.ResponseTransformConfig{
				ArrayOperations: []config.ArrayOperation{
					{Field: "items", Operation: config.ArrayOperationLimit, Value: 3},
				},
			},
			checkFunc: func(t *testing.T, result interface{}) {
				resultMap := result.(map[string]interface{})
				items := resultMap["items"].([]interface{})
				assert.Len(t, items, 3)
				assert.Equal(t, []interface{}{"a", "b", "c"}, items)
			},
		},
		{
			name: "sort array",
			response: map[string]interface{}{
				"items": []interface{}{
					map[string]interface{}{"name": "charlie"},
					map[string]interface{}{"name": "alice"},
					map[string]interface{}{"name": "bob"},
				},
			},
			cfg: &config.ResponseTransformConfig{
				ArrayOperations: []config.ArrayOperation{
					{Field: "items", Operation: config.ArrayOperationSort, Value: "name"},
				},
			},
			checkFunc: func(t *testing.T, result interface{}) {
				resultMap := result.(map[string]interface{})
				items := resultMap["items"].([]interface{})
				assert.Len(t, items, 3)
				assert.Equal(t, "alice", items[0].(map[string]interface{})["name"])
				assert.Equal(t, "bob", items[1].(map[string]interface{})["name"])
				assert.Equal(t, "charlie", items[2].(map[string]interface{})["name"])
			},
		},
		{
			name: "deduplicate array",
			response: map[string]interface{}{
				"items": []interface{}{"a", "b", "a", "c", "b"},
			},
			cfg: &config.ResponseTransformConfig{
				ArrayOperations: []config.ArrayOperation{
					{Field: "items", Operation: config.ArrayOperationDeduplicate},
				},
			},
			checkFunc: func(t *testing.T, result interface{}) {
				resultMap := result.(map[string]interface{})
				items := resultMap["items"].([]interface{})
				assert.Len(t, items, 3)
			},
		},
		{
			name: "append to array",
			response: map[string]interface{}{
				"items": []interface{}{"a", "b"},
			},
			cfg: &config.ResponseTransformConfig{
				ArrayOperations: []config.ArrayOperation{
					{Field: "items", Operation: config.ArrayOperationAppend, Value: "c"},
				},
			},
			checkFunc: func(t *testing.T, result interface{}) {
				resultMap := result.(map[string]interface{})
				items := resultMap["items"].([]interface{})
				assert.Len(t, items, 3)
				assert.Equal(t, "c", items[2])
			},
		},
		{
			name: "prepend to array",
			response: map[string]interface{}{
				"items": []interface{}{"b", "c"},
			},
			cfg: &config.ResponseTransformConfig{
				ArrayOperations: []config.ArrayOperation{
					{Field: "items", Operation: config.ArrayOperationPrepend, Value: "a"},
				},
			},
			checkFunc: func(t *testing.T, result interface{}) {
				resultMap := result.(map[string]interface{})
				items := resultMap["items"].([]interface{})
				assert.Len(t, items, 3)
				assert.Equal(t, "a", items[0])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := transformer.TransformResponse(context.Background(), tt.response, tt.cfg)
			require.NoError(t, err)
			tt.checkFunc(t, result)
		})
	}
}

func TestResponseTransformer_CombinedTransformations(t *testing.T) {
	transformer := NewResponseTransformer(observability.NopLogger())

	response := map[string]interface{}{
		"user_name":    "John",
		"user_email":   "john@example.com",
		"password":     "secret",
		"internal_id":  "abc123",
		"phone_number": "123-456-7890",
	}

	cfg := &config.ResponseTransformConfig{
		DenyFields: []string{"password", "internal_id"},
		FieldMappings: []config.FieldMapping{
			{Source: "user_name", Target: "name"},
			{Source: "user_email", Target: "email"},
			{Source: "phone_number", Target: "phone"},
		},
		GroupFields: []config.FieldGroup{
			{Name: "contact", Fields: []string{"email", "phone"}},
		},
	}

	result, err := transformer.TransformResponse(context.Background(), response, cfg)
	require.NoError(t, err)

	resultMap, ok := result.(map[string]interface{})
	require.True(t, ok)

	// Verify denied fields are removed
	assert.NotContains(t, resultMap, "password")
	assert.NotContains(t, resultMap, "internal_id")

	// Verify field mappings
	assert.Equal(t, "John", resultMap["name"])

	// Verify grouping
	contact, ok := resultMap["contact"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "john@example.com", contact["email"])
	assert.Equal(t, "123-456-7890", contact["phone"])
}

func TestResponseTransformer_ArrayFieldNotFound(t *testing.T) {
	transformer := NewResponseTransformer(observability.NopLogger())

	response := map[string]interface{}{
		"name": "test",
	}

	cfg := &config.ResponseTransformConfig{
		ArrayOperations: []config.ArrayOperation{
			{Field: "nonexistent", Operation: config.ArrayOperationLimit, Value: 10},
		},
	}

	// Should not error, just skip the operation
	result, err := transformer.TransformResponse(context.Background(), response, cfg)
	require.NoError(t, err)
	assert.Equal(t, "test", result.(map[string]interface{})["name"])
}

func TestResponseTransformer_UnknownArrayOperation(t *testing.T) {
	transformer := NewResponseTransformer(observability.NopLogger())

	response := map[string]interface{}{
		"items": []interface{}{"a", "b", "c"},
	}

	cfg := &config.ResponseTransformConfig{
		ArrayOperations: []config.ArrayOperation{
			{Field: "items", Operation: "unknown"},
		},
	}

	// Should not error, just skip the unknown operation
	result, err := transformer.TransformResponse(context.Background(), response, cfg)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestGetArrayAtPath(t *testing.T) {
	tests := []struct {
		name      string
		data      map[string]interface{}
		path      string
		expected  []interface{}
		expectErr bool
	}{
		{
			name: "simple array",
			data: map[string]interface{}{
				"items": []interface{}{"a", "b", "c"},
			},
			path:     "items",
			expected: []interface{}{"a", "b", "c"},
		},
		{
			name: "nested array",
			data: map[string]interface{}{
				"data": map[string]interface{}{
					"items": []interface{}{1, 2, 3},
				},
			},
			path:     "data.items",
			expected: []interface{}{1, 2, 3},
		},
		{
			name: "field not found",
			data: map[string]interface{}{
				"name": "test",
			},
			path:      "items",
			expectErr: true,
		},
		{
			name: "field is not array",
			data: map[string]interface{}{
				"items": "not an array",
			},
			path:      "items",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := getArrayAtPath(tt.data, tt.path)

			if tt.expectErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSetArrayAtPath(t *testing.T) {
	data := map[string]interface{}{
		"items": []interface{}{"a", "b"},
	}

	newArray := []interface{}{"x", "y", "z"}
	err := setArrayAtPath(data, "items", newArray)
	require.NoError(t, err)

	assert.Equal(t, newArray, data["items"])
}

func TestResponseTransformer_LimitArray_EdgeCases(t *testing.T) {
	transformer := NewResponseTransformer(observability.NopLogger())

	tests := []struct {
		name     string
		response interface{}
		limit    interface{}
		expected int
	}{
		{
			name: "limit with int",
			response: map[string]interface{}{
				"items": []interface{}{"a", "b", "c", "d", "e"},
			},
			limit:    3,
			expected: 3,
		},
		{
			name: "limit with int64",
			response: map[string]interface{}{
				"items": []interface{}{"a", "b", "c", "d", "e"},
			},
			limit:    int64(2),
			expected: 2,
		},
		{
			name: "limit with float64",
			response: map[string]interface{}{
				"items": []interface{}{"a", "b", "c", "d", "e"},
			},
			limit:    float64(4),
			expected: 4,
		},
		{
			name: "limit zero - no change",
			response: map[string]interface{}{
				"items": []interface{}{"a", "b", "c"},
			},
			limit:    0,
			expected: 3,
		},
		{
			name: "limit negative - no change",
			response: map[string]interface{}{
				"items": []interface{}{"a", "b", "c"},
			},
			limit:    -1,
			expected: 3,
		},
		{
			name: "limit greater than length - no change",
			response: map[string]interface{}{
				"items": []interface{}{"a", "b"},
			},
			limit:    10,
			expected: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.ResponseTransformConfig{
				ArrayOperations: []config.ArrayOperation{
					{Field: "items", Operation: config.ArrayOperationLimit, Value: tt.limit},
				},
			}

			result, err := transformer.TransformResponse(context.Background(), tt.response, cfg)
			require.NoError(t, err)

			resultMap := result.(map[string]interface{})
			items := resultMap["items"].([]interface{})
			assert.Len(t, items, tt.expected)
		})
	}
}

func TestResponseTransformer_SortArray_EmptyAndSingle(t *testing.T) {
	transformer := NewResponseTransformer(observability.NopLogger())

	tests := []struct {
		name     string
		response interface{}
		expected int
	}{
		{
			name: "empty array",
			response: map[string]interface{}{
				"items": []interface{}{},
			},
			expected: 0,
		},
		{
			name: "single element",
			response: map[string]interface{}{
				"items": []interface{}{map[string]interface{}{"name": "only"}},
			},
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.ResponseTransformConfig{
				ArrayOperations: []config.ArrayOperation{
					{Field: "items", Operation: config.ArrayOperationSort, Value: "name"},
				},
			}

			result, err := transformer.TransformResponse(context.Background(), tt.response, cfg)
			require.NoError(t, err)

			resultMap := result.(map[string]interface{})
			items := resultMap["items"].([]interface{})
			assert.Len(t, items, tt.expected)
		})
	}
}

func TestResponseTransformer_AppendPrepend_NilValue(t *testing.T) {
	transformer := NewResponseTransformer(observability.NopLogger())

	response := map[string]interface{}{
		"items": []interface{}{"a", "b"},
	}

	// Append nil - should not change array
	cfg := &config.ResponseTransformConfig{
		ArrayOperations: []config.ArrayOperation{
			{Field: "items", Operation: config.ArrayOperationAppend, Value: nil},
		},
	}

	result, err := transformer.TransformResponse(context.Background(), response, cfg)
	require.NoError(t, err)

	resultMap := result.(map[string]interface{})
	items := resultMap["items"].([]interface{})
	assert.Len(t, items, 2)
}

func TestResponseTransformer_FilterArray(t *testing.T) {
	transformer := NewResponseTransformer(observability.NopLogger())

	response := map[string]interface{}{
		"items": []interface{}{"a", "b", "c"},
	}

	// Filter with condition (simplified - returns all)
	cfg := &config.ResponseTransformConfig{
		ArrayOperations: []config.ArrayOperation{
			{Field: "items", Operation: config.ArrayOperationFilter, Condition: "item != 'b'"},
		},
	}

	result, err := transformer.TransformResponse(context.Background(), response, cfg)
	require.NoError(t, err)

	resultMap := result.(map[string]interface{})
	items := resultMap["items"].([]interface{})
	// Simplified filter returns all items
	assert.Len(t, items, 3)
}

func TestResponseTransformer_FilterArray_EmptyCondition(t *testing.T) {
	transformer := NewResponseTransformer(observability.NopLogger())

	response := map[string]interface{}{
		"items": []interface{}{"a", "b", "c"},
	}

	cfg := &config.ResponseTransformConfig{
		ArrayOperations: []config.ArrayOperation{
			{Field: "items", Operation: config.ArrayOperationFilter, Condition: ""},
		},
	}

	result, err := transformer.TransformResponse(context.Background(), response, cfg)
	require.NoError(t, err)

	resultMap := result.(map[string]interface{})
	items := resultMap["items"].([]interface{})
	assert.Len(t, items, 3)
}
