// Package transform provides data transformation capabilities for the API Gateway.
package transform

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestNewFieldMapper(t *testing.T) {
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
			mapper := NewFieldMapper(tt.logger)
			require.NotNil(t, mapper)
		})
	}
}

func TestFieldMapper_MapFields(t *testing.T) {
	mapper := NewFieldMapper(observability.NopLogger())

	tests := []struct {
		name      string
		data      map[string]interface{}
		mappings  []config.FieldMapping
		expected  map[string]interface{}
		expectErr bool
	}{
		{
			name: "empty mappings returns original data",
			data: map[string]interface{}{
				"name": "test",
			},
			mappings: []config.FieldMapping{},
			expected: map[string]interface{}{
				"name": "test",
			},
		},
		{
			name: "simple field rename",
			data: map[string]interface{}{
				"old_name": "test",
			},
			mappings: []config.FieldMapping{
				{Source: "old_name", Target: "new_name"},
			},
			expected: map[string]interface{}{
				"new_name": "test",
			},
		},
		{
			name: "multiple field renames",
			data: map[string]interface{}{
				"first_name": "John",
				"last_name":  "Doe",
			},
			mappings: []config.FieldMapping{
				{Source: "first_name", Target: "firstName"},
				{Source: "last_name", Target: "lastName"},
			},
			expected: map[string]interface{}{
				"firstName": "John",
				"lastName":  "Doe",
			},
		},
		{
			name: "nested field rename",
			data: map[string]interface{}{
				"user": map[string]interface{}{
					"old_name": "test",
				},
			},
			mappings: []config.FieldMapping{
				{Source: "user.old_name", Target: "user.new_name"},
			},
			expected: map[string]interface{}{
				"user": map[string]interface{}{
					"new_name": "test",
				},
			},
		},
		{
			name: "move field to different level",
			data: map[string]interface{}{
				"user": map[string]interface{}{
					"name": "test",
				},
			},
			mappings: []config.FieldMapping{
				{Source: "user.name", Target: "name"},
			},
			expected: map[string]interface{}{
				"user": map[string]interface{}{},
				"name": "test",
			},
		},
		{
			name: "source field not found - no error",
			data: map[string]interface{}{
				"name": "test",
			},
			mappings: []config.FieldMapping{
				{Source: "nonexistent", Target: "new_field"},
			},
			expected: map[string]interface{}{
				"name": "test",
			},
		},
		{
			name: "empty source or target - skipped",
			data: map[string]interface{}{
				"name": "test",
			},
			mappings: []config.FieldMapping{
				{Source: "", Target: "new_name"},
				{Source: "name", Target: ""},
			},
			expected: map[string]interface{}{
				"name": "test",
			},
		},
		{
			name: "rename preserves other fields",
			data: map[string]interface{}{
				"old_name": "test",
				"email":    "test@example.com",
				"age":      30,
			},
			mappings: []config.FieldMapping{
				{Source: "old_name", Target: "new_name"},
			},
			expected: map[string]interface{}{
				"new_name": "test",
				"email":    "test@example.com",
				"age":      30,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := mapper.MapFields(tt.data, tt.mappings)

			if tt.expectErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetValueAtPath(t *testing.T) {
	tests := []struct {
		name      string
		data      map[string]interface{}
		path      string
		expected  interface{}
		expectErr bool
	}{
		{
			name: "simple field",
			data: map[string]interface{}{
				"name": "test",
			},
			path:     "name",
			expected: "test",
		},
		{
			name: "nested field",
			data: map[string]interface{}{
				"user": map[string]interface{}{
					"name": "test",
				},
			},
			path:     "user.name",
			expected: "test",
		},
		{
			name: "deeply nested field",
			data: map[string]interface{}{
				"user": map[string]interface{}{
					"address": map[string]interface{}{
						"city": "NYC",
					},
				},
			},
			path:     "user.address.city",
			expected: "NYC",
		},
		{
			name: "array index",
			data: map[string]interface{}{
				"items": []interface{}{"a", "b", "c"},
			},
			path:     "items[0]",
			expected: "a",
		},
		{
			name: "array of objects",
			data: map[string]interface{}{
				"items": []interface{}{
					map[string]interface{}{"id": 1},
					map[string]interface{}{"id": 2},
				},
			},
			path:     "items[1].id",
			expected: 2,
		},
		{
			name: "field not found",
			data: map[string]interface{}{
				"name": "test",
			},
			path:      "email",
			expectErr: true,
		},
		{
			name: "nested field not found",
			data: map[string]interface{}{
				"user": map[string]interface{}{
					"name": "test",
				},
			},
			path:      "user.email",
			expectErr: true,
		},
		{
			name: "array index out of bounds",
			data: map[string]interface{}{
				"items": []interface{}{"a", "b"},
			},
			path:      "items[5]",
			expectErr: true,
		},
		{
			name:      "empty path",
			data:      map[string]interface{}{"name": "test"},
			path:      "",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := getValueAtPath(tt.data, tt.path)

			if tt.expectErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSetValueAtPath(t *testing.T) {
	tests := []struct {
		name      string
		data      map[string]interface{}
		path      string
		value     interface{}
		expected  map[string]interface{}
		expectErr bool
	}{
		{
			name:  "simple field",
			data:  map[string]interface{}{},
			path:  "name",
			value: "test",
			expected: map[string]interface{}{
				"name": "test",
			},
		},
		{
			name:  "nested field - creates intermediate",
			data:  map[string]interface{}{},
			path:  "user.name",
			value: "test",
			expected: map[string]interface{}{
				"user": map[string]interface{}{
					"name": "test",
				},
			},
		},
		{
			name: "overwrite existing field",
			data: map[string]interface{}{
				"name": "old",
			},
			path:  "name",
			value: "new",
			expected: map[string]interface{}{
				"name": "new",
			},
		},
		{
			name: "set nested in existing object",
			data: map[string]interface{}{
				"user": map[string]interface{}{
					"name": "test",
				},
			},
			path:  "user.email",
			value: "test@example.com",
			expected: map[string]interface{}{
				"user": map[string]interface{}{
					"name":  "test",
					"email": "test@example.com",
				},
			},
		},
		{
			name:  "set array element",
			data:  map[string]interface{}{},
			path:  "items[0]",
			value: "first",
			expected: map[string]interface{}{
				"items": []interface{}{"first"},
			},
		},
		{
			name:      "empty path",
			data:      map[string]interface{}{},
			path:      "",
			value:     "test",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := setValueAtPath(tt.data, tt.path, tt.value)

			if tt.expectErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, tt.data)
		})
	}
}

func TestDeleteValueAtPath(t *testing.T) {
	tests := []struct {
		name      string
		data      map[string]interface{}
		path      string
		expected  map[string]interface{}
		expectErr bool
	}{
		{
			name: "delete simple field",
			data: map[string]interface{}{
				"name":  "test",
				"email": "test@example.com",
			},
			path: "name",
			expected: map[string]interface{}{
				"email": "test@example.com",
			},
		},
		{
			name: "delete nested field",
			data: map[string]interface{}{
				"user": map[string]interface{}{
					"name":  "test",
					"email": "test@example.com",
				},
			},
			path: "user.name",
			expected: map[string]interface{}{
				"user": map[string]interface{}{
					"email": "test@example.com",
				},
			},
		},
		{
			name: "delete non-existent field - no error",
			data: map[string]interface{}{
				"name": "test",
			},
			path: "email",
			expected: map[string]interface{}{
				"name": "test",
			},
		},
		{
			name:      "empty path",
			data:      map[string]interface{}{"name": "test"},
			path:      "",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := deleteValueAtPath(tt.data, tt.path)

			if tt.expectErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, tt.data)
		})
	}
}

func TestParseFieldPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected []pathPart
	}{
		{
			name: "simple field",
			path: "name",
			expected: []pathPart{
				{Name: "name"},
			},
		},
		{
			name: "nested field",
			path: "user.name",
			expected: []pathPart{
				{Name: "user"},
				{Name: "name"},
			},
		},
		{
			name: "array index",
			path: "items[0]",
			expected: []pathPart{
				{Name: "items", IsArray: true, Index: 0},
			},
		},
		{
			name: "array with nested field",
			path: "items[0].name",
			expected: []pathPart{
				{Name: "items", IsArray: true, Index: 0},
				{Name: "name"},
			},
		},
		{
			name: "empty array notation",
			path: "items[]",
			expected: []pathPart{
				{Name: "items", IsArray: true, Index: -1},
			},
		},
		{
			name: "deeply nested with arrays",
			path: "users[0].addresses[1].city",
			expected: []pathPart{
				{Name: "users", IsArray: true, Index: 0},
				{Name: "addresses", IsArray: true, Index: 1},
				{Name: "city"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseFieldPath(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDeepCopyMap(t *testing.T) {
	tests := []struct {
		name string
		src  map[string]interface{}
	}{
		{
			name: "nil map",
			src:  nil,
		},
		{
			name: "empty map",
			src:  map[string]interface{}{},
		},
		{
			name: "simple map",
			src: map[string]interface{}{
				"name": "test",
				"age":  30,
			},
		},
		{
			name: "nested map",
			src: map[string]interface{}{
				"user": map[string]interface{}{
					"name": "test",
				},
			},
		},
		{
			name: "map with array",
			src: map[string]interface{}{
				"items": []interface{}{"a", "b", "c"},
			},
		},
		{
			name: "complex nested structure",
			src: map[string]interface{}{
				"user": map[string]interface{}{
					"name": "test",
					"addresses": []interface{}{
						map[string]interface{}{"city": "NYC"},
						map[string]interface{}{"city": "LA"},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := deepCopyMap(tt.src)

			if tt.src == nil {
				assert.Nil(t, result)
				return
			}

			assert.Equal(t, tt.src, result)

			// Verify it's a deep copy by modifying the original
			if len(tt.src) > 0 {
				tt.src["modified"] = true
				assert.NotContains(t, result, "modified")
			}
		})
	}
}

func TestGroupFields(t *testing.T) {
	tests := []struct {
		name     string
		data     map[string]interface{}
		groups   []config.FieldGroup
		expected map[string]interface{}
	}{
		{
			name: "empty groups",
			data: map[string]interface{}{
				"name":  "test",
				"email": "test@example.com",
			},
			groups: []config.FieldGroup{},
			expected: map[string]interface{}{
				"name":  "test",
				"email": "test@example.com",
			},
		},
		{
			name: "group fields into object",
			data: map[string]interface{}{
				"name":  "test",
				"email": "test@example.com",
				"phone": "123-456-7890",
				"age":   30,
			},
			groups: []config.FieldGroup{
				{Name: "contact", Fields: []string{"email", "phone"}},
			},
			expected: map[string]interface{}{
				"name": "test",
				"age":  30,
				"contact": map[string]interface{}{
					"email": "test@example.com",
					"phone": "123-456-7890",
				},
			},
		},
		{
			name: "multiple groups",
			data: map[string]interface{}{
				"firstName": "John",
				"lastName":  "Doe",
				"email":     "john@example.com",
				"phone":     "123-456-7890",
			},
			groups: []config.FieldGroup{
				{Name: "name", Fields: []string{"firstName", "lastName"}},
				{Name: "contact", Fields: []string{"email", "phone"}},
			},
			expected: map[string]interface{}{
				"name": map[string]interface{}{
					"firstName": "John",
					"lastName":  "Doe",
				},
				"contact": map[string]interface{}{
					"email": "john@example.com",
					"phone": "123-456-7890",
				},
			},
		},
		{
			name: "group with missing fields",
			data: map[string]interface{}{
				"name": "test",
			},
			groups: []config.FieldGroup{
				{Name: "contact", Fields: []string{"email", "phone"}},
			},
			expected: map[string]interface{}{
				"name": "test",
			},
		},
		{
			name: "empty group name - skipped",
			data: map[string]interface{}{
				"name": "test",
			},
			groups: []config.FieldGroup{
				{Name: "", Fields: []string{"name"}},
			},
			expected: map[string]interface{}{
				"name": "test",
			},
		},
		{
			name: "empty fields - skipped",
			data: map[string]interface{}{
				"name": "test",
			},
			groups: []config.FieldGroup{
				{Name: "group", Fields: []string{}},
			},
			expected: map[string]interface{}{
				"name": "test",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GroupFields(tt.data, tt.groups)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFlattenFields(t *testing.T) {
	tests := []struct {
		name     string
		data     map[string]interface{}
		fields   []string
		expected map[string]interface{}
	}{
		{
			name: "empty fields",
			data: map[string]interface{}{
				"user": map[string]interface{}{
					"name": "test",
				},
			},
			fields: []string{},
			expected: map[string]interface{}{
				"user": map[string]interface{}{
					"name": "test",
				},
			},
		},
		{
			name: "flatten nested object",
			data: map[string]interface{}{
				"metadata": map[string]interface{}{
					"created": "2024-01-01",
					"updated": "2024-01-02",
				},
				"name": "test",
			},
			fields: []string{"metadata"},
			expected: map[string]interface{}{
				"created": "2024-01-01",
				"updated": "2024-01-02",
				"name":    "test",
			},
		},
		{
			name: "flatten multiple objects",
			data: map[string]interface{}{
				"meta1": map[string]interface{}{
					"key1": "value1",
				},
				"meta2": map[string]interface{}{
					"key2": "value2",
				},
				"name": "test",
			},
			fields: []string{"meta1", "meta2"},
			expected: map[string]interface{}{
				"key1": "value1",
				"key2": "value2",
				"name": "test",
			},
		},
		{
			name: "flatten non-existent field - no change",
			data: map[string]interface{}{
				"name": "test",
			},
			fields: []string{"metadata"},
			expected: map[string]interface{}{
				"name": "test",
			},
		},
		{
			name: "flatten non-object field - no change",
			data: map[string]interface{}{
				"name":  "test",
				"count": 5,
			},
			fields: []string{"count"},
			expected: map[string]interface{}{
				"name":  "test",
				"count": 5,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FlattenFields(tt.data, tt.fields)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFieldMapper_DoesNotModifyOriginal(t *testing.T) {
	mapper := NewFieldMapper(observability.NopLogger())

	original := map[string]interface{}{
		"old_name": "test",
		"email":    "test@example.com",
	}

	// Make a copy to compare later
	originalCopy := map[string]interface{}{
		"old_name": "test",
		"email":    "test@example.com",
	}

	mappings := []config.FieldMapping{
		{Source: "old_name", Target: "new_name"},
	}

	result, err := mapper.MapFields(original, mappings)
	require.NoError(t, err)

	// Original should be unchanged
	assert.Equal(t, originalCopy, original)

	// Result should have the mapping applied
	assert.Contains(t, result, "new_name")
	assert.NotContains(t, result, "old_name")
}
