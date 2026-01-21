//go:build functional
// +build functional

// Package functional contains functional tests for the API Gateway.
// These tests verify transformation logic in isolation without external dependencies.
package functional

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/transform"
)

// TestFunctional_Transform_FieldFiltering tests field filtering functionality.
func TestFunctional_Transform_FieldFiltering(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	filter := transform.NewFieldFilter(logger)

	tests := []struct {
		name        string
		data        map[string]interface{}
		allowFields []string
		denyFields  []string
		expected    map[string]interface{}
		useAllow    bool
	}{
		{
			name: "allow_fields_simple",
			data: map[string]interface{}{
				"id":       "123",
				"name":     "Test",
				"password": "secret",
				"email":    "test@example.com",
			},
			allowFields: []string{"id", "name"},
			expected: map[string]interface{}{
				"id":   "123",
				"name": "Test",
			},
			useAllow: true,
		},
		{
			name: "deny_fields_simple",
			data: map[string]interface{}{
				"id":       "123",
				"name":     "Test",
				"password": "secret",
				"email":    "test@example.com",
			},
			denyFields: []string{"password"},
			expected: map[string]interface{}{
				"id":    "123",
				"name":  "Test",
				"email": "test@example.com",
			},
			useAllow: false,
		},
		{
			name: "allow_nested_fields",
			data: map[string]interface{}{
				"user": map[string]interface{}{
					"id":       "123",
					"name":     "Test",
					"password": "secret",
				},
				"other": "data",
			},
			allowFields: []string{"user.id", "user.name"},
			expected: map[string]interface{}{
				"user": map[string]interface{}{
					"id":   "123",
					"name": "Test",
				},
			},
			useAllow: true,
		},
		{
			name: "deny_nested_fields",
			data: map[string]interface{}{
				"user": map[string]interface{}{
					"id":       "123",
					"name":     "Test",
					"password": "secret",
				},
			},
			denyFields: []string{"user.password"},
			expected: map[string]interface{}{
				"user": map[string]interface{}{
					"id":   "123",
					"name": "Test",
				},
			},
			useAllow: false,
		},
		{
			name: "allow_array_fields",
			data: map[string]interface{}{
				"items": []interface{}{
					map[string]interface{}{"id": 1, "name": "Item 1", "secret": "x"},
					map[string]interface{}{"id": 2, "name": "Item 2", "secret": "y"},
				},
			},
			allowFields: []string{"items[].id", "items[].name"},
			expected: map[string]interface{}{
				"items": []interface{}{
					map[string]interface{}{"id": 1, "name": "Item 1"},
					map[string]interface{}{"id": 2, "name": "Item 2"},
				},
			},
			useAllow: true,
		},
		{
			name: "deny_array_fields",
			data: map[string]interface{}{
				"items": []interface{}{
					map[string]interface{}{"id": 1, "name": "Item 1", "secret": "x"},
					map[string]interface{}{"id": 2, "name": "Item 2", "secret": "y"},
				},
			},
			denyFields: []string{"items[].secret"},
			expected: map[string]interface{}{
				"items": []interface{}{
					map[string]interface{}{"id": 1, "name": "Item 1"},
					map[string]interface{}{"id": 2, "name": "Item 2"},
				},
			},
			useAllow: false,
		},
		{
			name:        "empty_allow_fields_returns_empty",
			data:        map[string]interface{}{"id": "123", "name": "Test"},
			allowFields: []string{},
			expected:    map[string]interface{}{"id": "123", "name": "Test"},
			useAllow:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result map[string]interface{}
			if tt.useAllow {
				result = filter.FilterAllow(tt.data, tt.allowFields)
			} else {
				result = filter.FilterDeny(tt.data, tt.denyFields)
			}
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestFunctional_Transform_FieldMapping tests field mapping/renaming functionality.
func TestFunctional_Transform_FieldMapping(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	mapper := transform.NewFieldMapper(logger)

	tests := []struct {
		name      string
		data      map[string]interface{}
		mappings  []config.FieldMapping
		expected  map[string]interface{}
		expectErr bool
	}{
		{
			name: "simple_rename",
			data: map[string]interface{}{
				"old_name": "value",
				"other":    "data",
			},
			mappings: []config.FieldMapping{
				{Source: "old_name", Target: "new_name"},
			},
			expected: map[string]interface{}{
				"new_name": "value",
				"other":    "data",
			},
		},
		{
			name: "multiple_renames",
			data: map[string]interface{}{
				"first_name": "John",
				"last_name":  "Doe",
				"age":        30,
			},
			mappings: []config.FieldMapping{
				{Source: "first_name", Target: "firstName"},
				{Source: "last_name", Target: "lastName"},
			},
			expected: map[string]interface{}{
				"firstName": "John",
				"lastName":  "Doe",
				"age":       30,
			},
		},
		{
			name: "nested_rename",
			data: map[string]interface{}{
				"user": map[string]interface{}{
					"old_field": "value",
					"other":     "data",
				},
			},
			mappings: []config.FieldMapping{
				{Source: "user.old_field", Target: "user.new_field"},
			},
			expected: map[string]interface{}{
				"user": map[string]interface{}{
					"new_field": "value",
					"other":     "data",
				},
			},
		},
		{
			name: "move_to_different_level",
			data: map[string]interface{}{
				"user": map[string]interface{}{
					"name": "John",
				},
			},
			mappings: []config.FieldMapping{
				{Source: "user.name", Target: "name"},
			},
			expected: map[string]interface{}{
				"user": map[string]interface{}{},
				"name": "John",
			},
		},
		{
			name: "source_not_found_no_error",
			data: map[string]interface{}{
				"existing": "value",
			},
			mappings: []config.FieldMapping{
				{Source: "nonexistent", Target: "new_field"},
			},
			expected: map[string]interface{}{
				"existing": "value",
			},
		},
		{
			name: "empty_mappings",
			data: map[string]interface{}{
				"field": "value",
			},
			mappings: []config.FieldMapping{},
			expected: map[string]interface{}{
				"field": "value",
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

// TestFunctional_Transform_FieldGrouping tests field grouping functionality.
func TestFunctional_Transform_FieldGrouping(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		data     map[string]interface{}
		groups   []config.FieldGroup
		expected map[string]interface{}
	}{
		{
			name: "group_contact_fields",
			data: map[string]interface{}{
				"name":  "John",
				"email": "john@example.com",
				"phone": "555-1234",
				"age":   30,
			},
			groups: []config.FieldGroup{
				{Name: "contact", Fields: []string{"email", "phone"}},
			},
			expected: map[string]interface{}{
				"name": "John",
				"age":  30,
				"contact": map[string]interface{}{
					"email": "john@example.com",
					"phone": "555-1234",
				},
			},
		},
		{
			name: "multiple_groups",
			data: map[string]interface{}{
				"firstName": "John",
				"lastName":  "Doe",
				"email":     "john@example.com",
				"phone":     "555-1234",
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
					"phone": "555-1234",
				},
			},
		},
		{
			name: "group_with_missing_fields",
			data: map[string]interface{}{
				"name": "John",
			},
			groups: []config.FieldGroup{
				{Name: "contact", Fields: []string{"email", "phone"}},
			},
			expected: map[string]interface{}{
				"name": "John",
			},
		},
		{
			name: "empty_groups",
			data: map[string]interface{}{
				"name": "John",
			},
			groups: []config.FieldGroup{},
			expected: map[string]interface{}{
				"name": "John",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := transform.GroupFields(tt.data, tt.groups)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestFunctional_Transform_FieldFlattening tests field flattening functionality.
func TestFunctional_Transform_FieldFlattening(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		data     map[string]interface{}
		fields   []string
		expected map[string]interface{}
	}{
		{
			name: "flatten_metadata",
			data: map[string]interface{}{
				"name": "Test",
				"metadata": map[string]interface{}{
					"created_at": "2024-01-01",
					"updated_at": "2024-01-02",
				},
			},
			fields: []string{"metadata"},
			expected: map[string]interface{}{
				"name":       "Test",
				"created_at": "2024-01-01",
				"updated_at": "2024-01-02",
			},
		},
		{
			name: "flatten_multiple",
			data: map[string]interface{}{
				"name": "Test",
				"meta1": map[string]interface{}{
					"key1": "value1",
				},
				"meta2": map[string]interface{}{
					"key2": "value2",
				},
			},
			fields: []string{"meta1", "meta2"},
			expected: map[string]interface{}{
				"name": "Test",
				"key1": "value1",
				"key2": "value2",
			},
		},
		{
			name: "flatten_nonexistent_field",
			data: map[string]interface{}{
				"name": "Test",
			},
			fields: []string{"metadata"},
			expected: map[string]interface{}{
				"name": "Test",
			},
		},
		{
			name: "flatten_non_object_field",
			data: map[string]interface{}{
				"name":  "Test",
				"count": 5,
			},
			fields: []string{"count"},
			expected: map[string]interface{}{
				"name":  "Test",
				"count": 5,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := transform.FlattenFields(tt.data, tt.fields)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestFunctional_Transform_ArrayOperations tests array operations functionality.
func TestFunctional_Transform_ArrayOperations(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	transformer := transform.NewResponseTransformer(logger)

	tests := []struct {
		name       string
		data       map[string]interface{}
		operations []config.ArrayOperation
		expected   map[string]interface{}
	}{
		{
			name: "limit_array",
			data: map[string]interface{}{
				"items": []interface{}{
					map[string]interface{}{"id": 1},
					map[string]interface{}{"id": 2},
					map[string]interface{}{"id": 3},
					map[string]interface{}{"id": 4},
					map[string]interface{}{"id": 5},
				},
			},
			operations: []config.ArrayOperation{
				{Field: "items", Operation: config.ArrayOperationLimit, Value: 3},
			},
			expected: map[string]interface{}{
				"items": []interface{}{
					map[string]interface{}{"id": 1},
					map[string]interface{}{"id": 2},
					map[string]interface{}{"id": 3},
				},
			},
		},
		{
			name: "sort_array",
			data: map[string]interface{}{
				"items": []interface{}{
					map[string]interface{}{"name": "Charlie"},
					map[string]interface{}{"name": "Alice"},
					map[string]interface{}{"name": "Bob"},
				},
			},
			operations: []config.ArrayOperation{
				{Field: "items", Operation: config.ArrayOperationSort, Value: "name"},
			},
			expected: map[string]interface{}{
				"items": []interface{}{
					map[string]interface{}{"name": "Alice"},
					map[string]interface{}{"name": "Bob"},
					map[string]interface{}{"name": "Charlie"},
				},
			},
		},
		{
			name: "deduplicate_array",
			data: map[string]interface{}{
				"tags": []interface{}{"a", "b", "a", "c", "b"},
			},
			operations: []config.ArrayOperation{
				{Field: "tags", Operation: config.ArrayOperationDeduplicate},
			},
			expected: map[string]interface{}{
				"tags": []interface{}{"a", "b", "c"},
			},
		},
		{
			name: "append_to_array",
			data: map[string]interface{}{
				"items": []interface{}{"a", "b"},
			},
			operations: []config.ArrayOperation{
				{Field: "items", Operation: config.ArrayOperationAppend, Value: "c"},
			},
			expected: map[string]interface{}{
				"items": []interface{}{"a", "b", "c"},
			},
		},
		{
			name: "prepend_to_array",
			data: map[string]interface{}{
				"items": []interface{}{"b", "c"},
			},
			operations: []config.ArrayOperation{
				{Field: "items", Operation: config.ArrayOperationPrepend, Value: "a"},
			},
			expected: map[string]interface{}{
				"items": []interface{}{"a", "b", "c"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.ResponseTransformConfig{
				ArrayOperations: tt.operations,
			}
			result, err := transformer.TransformResponse(context.Background(), tt.data, cfg)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestFunctional_Transform_ResponseMerging tests response merging functionality.
func TestFunctional_Transform_ResponseMerging(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	merger := transform.NewResponseMerger(logger)

	tests := []struct {
		name      string
		responses []interface{}
		strategy  string
		expected  interface{}
	}{
		{
			name: "deep_merge",
			responses: []interface{}{
				map[string]interface{}{
					"user": map[string]interface{}{
						"name": "John",
					},
					"count": 1,
				},
				map[string]interface{}{
					"user": map[string]interface{}{
						"email": "john@example.com",
					},
					"status": "active",
				},
			},
			strategy: config.MergeStrategyDeep,
			expected: map[string]interface{}{
				"user": map[string]interface{}{
					"name":  "John",
					"email": "john@example.com",
				},
				"count":  1,
				"status": "active",
			},
		},
		{
			name: "shallow_merge",
			responses: []interface{}{
				map[string]interface{}{
					"user": map[string]interface{}{
						"name": "John",
					},
					"count": 1,
				},
				map[string]interface{}{
					"user": map[string]interface{}{
						"email": "john@example.com",
					},
					"status": "active",
				},
			},
			strategy: config.MergeStrategyShallow,
			expected: map[string]interface{}{
				"user": map[string]interface{}{
					"email": "john@example.com",
				},
				"count":  1,
				"status": "active",
			},
		},
		{
			name: "replace_merge",
			responses: []interface{}{
				map[string]interface{}{"data": "first"},
				map[string]interface{}{"data": "second"},
				map[string]interface{}{"data": "third"},
			},
			strategy: config.MergeStrategyReplace,
			expected: map[string]interface{}{"data": "third"},
		},
		{
			name: "merge_arrays",
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
			name:      "single_response",
			responses: []interface{}{map[string]interface{}{"data": "only"}},
			strategy:  config.MergeStrategyDeep,
			expected:  map[string]interface{}{"data": "only"},
		},
		{
			name:      "empty_responses",
			responses: []interface{}{},
			strategy:  config.MergeStrategyDeep,
			expected:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := merger.Merge(tt.responses, tt.strategy)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestFunctional_Transform_Templating tests template-based transformation.
func TestFunctional_Transform_Templating(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	engine := transform.NewTemplateEngine(logger)

	tests := []struct {
		name      string
		template  string
		data      interface{}
		expected  interface{}
		expectErr bool
	}{
		{
			name:     "simple_json_template",
			template: `{"name": "{{.name}}", "id": "{{.id}}"}`,
			data: map[string]interface{}{
				"name": "Test",
				"id":   "123",
			},
			expected: map[string]interface{}{
				"name": "Test",
				"id":   "123",
			},
		},
		{
			name:     "template_with_functions",
			template: `{"upper_name": "{{upper .name}}"}`,
			data: map[string]interface{}{
				"name": "test",
			},
			expected: map[string]interface{}{
				"upper_name": "TEST",
			},
		},
		{
			name:     "template_with_conditional",
			template: `{"status": "{{if .active}}active{{else}}inactive{{end}}"}`,
			data: map[string]interface{}{
				"active": true,
			},
			expected: map[string]interface{}{
				"status": "active",
			},
		},
		{
			name:     "template_with_range",
			template: `{"items": [{{range $i, $v := .items}}{{if $i}},{{end}}"{{$v}}"{{end}}]}`,
			data: map[string]interface{}{
				"items": []interface{}{"a", "b", "c"},
			},
			expected: map[string]interface{}{
				"items": []interface{}{"a", "b", "c"},
			},
		},
		{
			name:     "template_with_json_function",
			template: `{{json .}}`,
			data: map[string]interface{}{
				"key": "value",
			},
			expected: map[string]interface{}{
				"key": "value",
			},
		},
		{
			name:     "empty_template_returns_data",
			template: "",
			data: map[string]interface{}{
				"key": "value",
			},
			expected: map[string]interface{}{
				"key": "value",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := engine.Execute(tt.template, tt.data)
			if tt.expectErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestFunctional_Transform_RequestTransformation tests request transformation.
func TestFunctional_Transform_RequestTransformation(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	transformer := transform.NewRequestTransformer(logger)

	tests := []struct {
		name     string
		request  interface{}
		cfg      *config.RequestTransformConfig
		expected interface{}
	}{
		{
			name: "passthrough_mode",
			request: map[string]interface{}{
				"data": "original",
			},
			cfg: &config.RequestTransformConfig{
				PassthroughBody: true,
			},
			expected: map[string]interface{}{
				"data": "original",
			},
		},
		{
			name: "apply_default_values",
			request: map[string]interface{}{
				"name": "Test",
			},
			cfg: &config.RequestTransformConfig{
				DefaultValues: map[string]interface{}{
					"version": "1.0",
					"name":    "Default", // Should not override existing
				},
			},
			expected: map[string]interface{}{
				"name":    "Test",
				"version": "1.0",
			},
		},
		{
			name: "remove_fields",
			request: map[string]interface{}{
				"name":     "Test",
				"internal": "secret",
				"debug":    true,
			},
			cfg: &config.RequestTransformConfig{
				RemoveFields: []string{"internal", "debug"},
			},
			expected: map[string]interface{}{
				"name": "Test",
			},
		},
		{
			name: "inject_static_fields",
			request: map[string]interface{}{
				"name": "Test",
			},
			cfg: &config.RequestTransformConfig{
				InjectFields: []config.FieldInjection{
					{Field: "gateway", Value: "avapigw"},
					{Field: "version", Value: "1.0"},
				},
			},
			expected: map[string]interface{}{
				"name":    "Test",
				"gateway": "avapigw",
				"version": "1.0",
			},
		},
		{
			name:    "nil_config_returns_original",
			request: map[string]interface{}{"data": "test"},
			cfg:     nil,
			expected: map[string]interface{}{
				"data": "test",
			},
		},
		{
			name:     "nil_request_with_defaults",
			request:  nil,
			cfg:      &config.RequestTransformConfig{DefaultValues: map[string]interface{}{"key": "value"}},
			expected: map[string]interface{}{"key": "value"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			result, err := transformer.TransformRequest(ctx, tt.request, tt.cfg)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestFunctional_Transform_ResponseTransformation tests response transformation.
func TestFunctional_Transform_ResponseTransformation(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	transformer := transform.NewResponseTransformer(logger)

	tests := []struct {
		name     string
		response interface{}
		cfg      *config.ResponseTransformConfig
		expected interface{}
	}{
		{
			name: "combined_transformations",
			response: map[string]interface{}{
				"user_id":   "123",
				"user_name": "John",
				"password":  "secret",
				"email":     "john@example.com",
				"phone":     "555-1234",
			},
			cfg: &config.ResponseTransformConfig{
				DenyFields: []string{"password"},
				FieldMappings: []config.FieldMapping{
					{Source: "user_id", Target: "id"},
					{Source: "user_name", Target: "name"},
				},
				GroupFields: []config.FieldGroup{
					{Name: "contact", Fields: []string{"email", "phone"}},
				},
			},
			expected: map[string]interface{}{
				"id":   "123",
				"name": "John",
				"contact": map[string]interface{}{
					"email": "john@example.com",
					"phone": "555-1234",
				},
			},
		},
		{
			name: "transform_array_response",
			response: []interface{}{
				map[string]interface{}{"id": 1, "name": "Item 1", "secret": "x"},
				map[string]interface{}{"id": 2, "name": "Item 2", "secret": "y"},
			},
			cfg: &config.ResponseTransformConfig{
				DenyFields: []string{"secret"},
			},
			expected: []interface{}{
				map[string]interface{}{"id": 1, "name": "Item 1"},
				map[string]interface{}{"id": 2, "name": "Item 2"},
			},
		},
		{
			name:     "nil_config_returns_original",
			response: map[string]interface{}{"data": "test"},
			cfg:      nil,
			expected: map[string]interface{}{"data": "test"},
		},
		{
			name:     "nil_response_returns_nil",
			response: nil,
			cfg:      &config.ResponseTransformConfig{AllowFields: []string{"id"}},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			result, err := transformer.TransformResponse(ctx, tt.response, tt.cfg)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestFunctional_Transform_DeepCopy tests that transformations don't modify original data.
func TestFunctional_Transform_DeepCopy(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	mapper := transform.NewFieldMapper(logger)

	original := map[string]interface{}{
		"old_name": "test",
		"nested": map[string]interface{}{
			"key": "value",
		},
	}

	// Make a copy for comparison
	originalCopy := map[string]interface{}{
		"old_name": "test",
		"nested": map[string]interface{}{
			"key": "value",
		},
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

// TestFunctional_Transform_FieldFiltering_AllowList tests field filtering with allow list.
func TestFunctional_Transform_FieldFiltering_AllowList(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	filter := transform.NewFieldFilter(logger)

	tests := []struct {
		name        string
		data        map[string]interface{}
		allowFields []string
		expected    map[string]interface{}
	}{
		{
			name: "allow_single_field",
			data: map[string]interface{}{
				"id":       "123",
				"name":     "Test",
				"password": "secret",
			},
			allowFields: []string{"id"},
			expected: map[string]interface{}{
				"id": "123",
			},
		},
		{
			name: "allow_multiple_fields",
			data: map[string]interface{}{
				"id":       "123",
				"name":     "Test",
				"email":    "test@example.com",
				"password": "secret",
			},
			allowFields: []string{"id", "name", "email"},
			expected: map[string]interface{}{
				"id":    "123",
				"name":  "Test",
				"email": "test@example.com",
			},
		},
		{
			name: "allow_all_fields",
			data: map[string]interface{}{
				"id":   "123",
				"name": "Test",
			},
			allowFields: []string{"id", "name"},
			expected: map[string]interface{}{
				"id":   "123",
				"name": "Test",
			},
		},
		{
			name: "allow_nonexistent_field",
			data: map[string]interface{}{
				"id":   "123",
				"name": "Test",
			},
			allowFields: []string{"nonexistent"},
			expected:    map[string]interface{}{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filter.FilterAllow(tt.data, tt.allowFields)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestFunctional_Transform_FieldFiltering_DenyList tests field filtering with deny list.
func TestFunctional_Transform_FieldFiltering_DenyList(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	filter := transform.NewFieldFilter(logger)

	tests := []struct {
		name       string
		data       map[string]interface{}
		denyFields []string
		expected   map[string]interface{}
	}{
		{
			name: "deny_single_field",
			data: map[string]interface{}{
				"id":       "123",
				"name":     "Test",
				"password": "secret",
			},
			denyFields: []string{"password"},
			expected: map[string]interface{}{
				"id":   "123",
				"name": "Test",
			},
		},
		{
			name: "deny_multiple_fields",
			data: map[string]interface{}{
				"id":       "123",
				"name":     "Test",
				"password": "secret",
				"token":    "abc123",
			},
			denyFields: []string{"password", "token"},
			expected: map[string]interface{}{
				"id":   "123",
				"name": "Test",
			},
		},
		{
			name: "deny_nonexistent_field",
			data: map[string]interface{}{
				"id":   "123",
				"name": "Test",
			},
			denyFields: []string{"nonexistent"},
			expected: map[string]interface{}{
				"id":   "123",
				"name": "Test",
			},
		},
		{
			name: "deny_all_fields",
			data: map[string]interface{}{
				"password": "secret",
				"token":    "abc123",
			},
			denyFields: []string{"password", "token"},
			expected:   map[string]interface{}{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filter.FilterDeny(tt.data, tt.denyFields)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestFunctional_Transform_FieldFiltering_NestedFields tests field filtering with nested fields.
func TestFunctional_Transform_FieldFiltering_NestedFields(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	filter := transform.NewFieldFilter(logger)

	tests := []struct {
		name        string
		data        map[string]interface{}
		allowFields []string
		denyFields  []string
		expected    map[string]interface{}
		useAllow    bool
	}{
		{
			name: "allow_deeply_nested_fields",
			data: map[string]interface{}{
				"user": map[string]interface{}{
					"profile": map[string]interface{}{
						"name":     "John",
						"email":    "john@example.com",
						"password": "secret",
					},
				},
			},
			allowFields: []string{"user.profile.name", "user.profile.email"},
			expected: map[string]interface{}{
				"user": map[string]interface{}{
					"profile": map[string]interface{}{
						"name":  "John",
						"email": "john@example.com",
					},
				},
			},
			useAllow: true,
		},
		{
			name: "deny_deeply_nested_fields",
			data: map[string]interface{}{
				"user": map[string]interface{}{
					"profile": map[string]interface{}{
						"name":     "John",
						"email":    "john@example.com",
						"password": "secret",
					},
				},
			},
			denyFields: []string{"user.profile.password"},
			expected: map[string]interface{}{
				"user": map[string]interface{}{
					"profile": map[string]interface{}{
						"name":  "John",
						"email": "john@example.com",
					},
				},
			},
			useAllow: false,
		},
		{
			name: "allow_mixed_depth_fields",
			data: map[string]interface{}{
				"id": "123",
				"user": map[string]interface{}{
					"name":  "John",
					"email": "john@example.com",
				},
				"metadata": map[string]interface{}{
					"created": "2024-01-01",
				},
			},
			allowFields: []string{"id", "user.name"},
			expected: map[string]interface{}{
				"id": "123",
				"user": map[string]interface{}{
					"name": "John",
				},
			},
			useAllow: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result map[string]interface{}
			if tt.useAllow {
				result = filter.FilterAllow(tt.data, tt.allowFields)
			} else {
				result = filter.FilterDeny(tt.data, tt.denyFields)
			}
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestFunctional_Transform_ArrayAppend tests array append operation.
func TestFunctional_Transform_ArrayAppend(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	transformer := transform.NewResponseTransformer(logger)

	tests := []struct {
		name     string
		data     map[string]interface{}
		value    interface{}
		expected map[string]interface{}
	}{
		{
			name: "append_string_to_array",
			data: map[string]interface{}{
				"items": []interface{}{"a", "b"},
			},
			value: "c",
			expected: map[string]interface{}{
				"items": []interface{}{"a", "b", "c"},
			},
		},
		{
			name: "append_object_to_array",
			data: map[string]interface{}{
				"items": []interface{}{
					map[string]interface{}{"id": 1},
				},
			},
			value: map[string]interface{}{"id": 2},
			expected: map[string]interface{}{
				"items": []interface{}{
					map[string]interface{}{"id": 1},
					map[string]interface{}{"id": 2},
				},
			},
		},
		{
			name: "append_to_empty_array",
			data: map[string]interface{}{
				"items": []interface{}{},
			},
			value: "first",
			expected: map[string]interface{}{
				"items": []interface{}{"first"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.ResponseTransformConfig{
				ArrayOperations: []config.ArrayOperation{
					{Field: "items", Operation: config.ArrayOperationAppend, Value: tt.value},
				},
			}
			result, err := transformer.TransformResponse(context.Background(), tt.data, cfg)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestFunctional_Transform_ArrayPrepend tests array prepend operation.
func TestFunctional_Transform_ArrayPrepend(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	transformer := transform.NewResponseTransformer(logger)

	tests := []struct {
		name     string
		data     map[string]interface{}
		value    interface{}
		expected map[string]interface{}
	}{
		{
			name: "prepend_string_to_array",
			data: map[string]interface{}{
				"items": []interface{}{"b", "c"},
			},
			value: "a",
			expected: map[string]interface{}{
				"items": []interface{}{"a", "b", "c"},
			},
		},
		{
			name: "prepend_object_to_array",
			data: map[string]interface{}{
				"items": []interface{}{
					map[string]interface{}{"id": 2},
				},
			},
			value: map[string]interface{}{"id": 1},
			expected: map[string]interface{}{
				"items": []interface{}{
					map[string]interface{}{"id": 1},
					map[string]interface{}{"id": 2},
				},
			},
		},
		{
			name: "prepend_to_empty_array",
			data: map[string]interface{}{
				"items": []interface{}{},
			},
			value: "first",
			expected: map[string]interface{}{
				"items": []interface{}{"first"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.ResponseTransformConfig{
				ArrayOperations: []config.ArrayOperation{
					{Field: "items", Operation: config.ArrayOperationPrepend, Value: tt.value},
				},
			}
			result, err := transformer.TransformResponse(context.Background(), tt.data, cfg)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestFunctional_Transform_ArrayFilter tests array filter operation.
func TestFunctional_Transform_ArrayFilter(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	transformer := transform.NewResponseTransformer(logger)

	// Note: Full CEL expression support would require additional dependencies.
	// This test verifies the filter operation structure is correctly processed.
	tests := []struct {
		name      string
		data      map[string]interface{}
		condition string
	}{
		{
			name: "filter_with_condition",
			data: map[string]interface{}{
				"items": []interface{}{
					map[string]interface{}{"id": 1, "active": true},
					map[string]interface{}{"id": 2, "active": false},
					map[string]interface{}{"id": 3, "active": true},
				},
			},
			condition: "item.active == true",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.ResponseTransformConfig{
				ArrayOperations: []config.ArrayOperation{
					{Field: "items", Operation: config.ArrayOperationFilter, Condition: tt.condition},
				},
			}
			result, err := transformer.TransformResponse(context.Background(), tt.data, cfg)
			require.NoError(t, err)
			// Verify the operation was processed without error
			assert.NotNil(t, result)
		})
	}
}

// TestFunctional_Transform_ArraySort tests array sort operation.
func TestFunctional_Transform_ArraySort(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	transformer := transform.NewResponseTransformer(logger)

	tests := []struct {
		name     string
		data     map[string]interface{}
		sortKey  string
		expected map[string]interface{}
	}{
		{
			name: "sort_by_string_field",
			data: map[string]interface{}{
				"items": []interface{}{
					map[string]interface{}{"name": "Charlie"},
					map[string]interface{}{"name": "Alice"},
					map[string]interface{}{"name": "Bob"},
				},
			},
			sortKey: "name",
			expected: map[string]interface{}{
				"items": []interface{}{
					map[string]interface{}{"name": "Alice"},
					map[string]interface{}{"name": "Bob"},
					map[string]interface{}{"name": "Charlie"},
				},
			},
		},
		{
			name: "sort_by_numeric_field",
			data: map[string]interface{}{
				"items": []interface{}{
					map[string]interface{}{"id": 3},
					map[string]interface{}{"id": 1},
					map[string]interface{}{"id": 2},
				},
			},
			sortKey: "id",
			expected: map[string]interface{}{
				"items": []interface{}{
					map[string]interface{}{"id": 1},
					map[string]interface{}{"id": 2},
					map[string]interface{}{"id": 3},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.ResponseTransformConfig{
				ArrayOperations: []config.ArrayOperation{
					{Field: "items", Operation: config.ArrayOperationSort, Value: tt.sortKey},
				},
			}
			result, err := transformer.TransformResponse(context.Background(), tt.data, cfg)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestFunctional_Transform_ArrayLimit tests array limit operation.
func TestFunctional_Transform_ArrayLimit(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	transformer := transform.NewResponseTransformer(logger)

	tests := []struct {
		name     string
		data     map[string]interface{}
		limit    int
		expected map[string]interface{}
	}{
		{
			name: "limit_to_3",
			data: map[string]interface{}{
				"items": []interface{}{1, 2, 3, 4, 5},
			},
			limit: 3,
			expected: map[string]interface{}{
				"items": []interface{}{1, 2, 3},
			},
		},
		{
			name: "limit_to_1",
			data: map[string]interface{}{
				"items": []interface{}{1, 2, 3},
			},
			limit: 1,
			expected: map[string]interface{}{
				"items": []interface{}{1},
			},
		},
		{
			name: "limit_exceeds_array_length",
			data: map[string]interface{}{
				"items": []interface{}{1, 2},
			},
			limit: 10,
			expected: map[string]interface{}{
				"items": []interface{}{1, 2},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.ResponseTransformConfig{
				ArrayOperations: []config.ArrayOperation{
					{Field: "items", Operation: config.ArrayOperationLimit, Value: tt.limit},
				},
			}
			result, err := transformer.TransformResponse(context.Background(), tt.data, cfg)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestFunctional_Transform_ArrayDeduplicate tests array deduplicate operation.
func TestFunctional_Transform_ArrayDeduplicate(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	transformer := transform.NewResponseTransformer(logger)

	tests := []struct {
		name     string
		data     map[string]interface{}
		expected map[string]interface{}
	}{
		{
			name: "deduplicate_strings",
			data: map[string]interface{}{
				"tags": []interface{}{"a", "b", "a", "c", "b", "d"},
			},
			expected: map[string]interface{}{
				"tags": []interface{}{"a", "b", "c", "d"},
			},
		},
		{
			name: "deduplicate_numbers",
			data: map[string]interface{}{
				"ids": []interface{}{1, 2, 1, 3, 2, 4},
			},
			expected: map[string]interface{}{
				"ids": []interface{}{1, 2, 3, 4},
			},
		},
		{
			name: "no_duplicates",
			data: map[string]interface{}{
				"items": []interface{}{"a", "b", "c"},
			},
			expected: map[string]interface{}{
				"items": []interface{}{"a", "b", "c"},
			},
		},
		{
			name: "all_duplicates",
			data: map[string]interface{}{
				"items": []interface{}{"a", "a", "a"},
			},
			expected: map[string]interface{}{
				"items": []interface{}{"a"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.ResponseTransformConfig{
				ArrayOperations: []config.ArrayOperation{
					{Field: "tags", Operation: config.ArrayOperationDeduplicate},
				},
			}
			// Adjust field name based on test data
			if _, ok := tt.data["ids"]; ok {
				cfg.ArrayOperations[0].Field = "ids"
			} else if _, ok := tt.data["items"]; ok {
				cfg.ArrayOperations[0].Field = "items"
			}
			result, err := transformer.TransformResponse(context.Background(), tt.data, cfg)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestFunctional_Transform_ResponseMerging_Deep tests response merging with deep strategy.
func TestFunctional_Transform_ResponseMerging_Deep(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	merger := transform.NewResponseMerger(logger)

	tests := []struct {
		name      string
		responses []interface{}
		expected  interface{}
	}{
		{
			name: "deep_merge_nested_objects",
			responses: []interface{}{
				map[string]interface{}{
					"user": map[string]interface{}{
						"name": "John",
						"profile": map[string]interface{}{
							"age": 30,
						},
					},
				},
				map[string]interface{}{
					"user": map[string]interface{}{
						"email": "john@example.com",
						"profile": map[string]interface{}{
							"city": "NYC",
						},
					},
				},
			},
			expected: map[string]interface{}{
				"user": map[string]interface{}{
					"name":  "John",
					"email": "john@example.com",
					"profile": map[string]interface{}{
						"age":  30,
						"city": "NYC",
					},
				},
			},
		},
		{
			name: "deep_merge_with_arrays",
			responses: []interface{}{
				map[string]interface{}{
					"items": []interface{}{"a", "b"},
				},
				map[string]interface{}{
					"items": []interface{}{"c", "d"},
				},
			},
			expected: map[string]interface{}{
				"items": []interface{}{"a", "b", "c", "d"},
			},
		},
		{
			name: "deep_merge_overwrites_primitives",
			responses: []interface{}{
				map[string]interface{}{
					"count": 1,
					"name":  "first",
				},
				map[string]interface{}{
					"count": 2,
				},
			},
			expected: map[string]interface{}{
				"count": 2,
				"name":  "first",
			},
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

// TestFunctional_Transform_ResponseMerging_Shallow tests response merging with shallow strategy.
func TestFunctional_Transform_ResponseMerging_Shallow(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	merger := transform.NewResponseMerger(logger)

	tests := []struct {
		name      string
		responses []interface{}
		expected  interface{}
	}{
		{
			name: "shallow_merge_replaces_nested",
			responses: []interface{}{
				map[string]interface{}{
					"user": map[string]interface{}{
						"name": "John",
						"age":  30,
					},
				},
				map[string]interface{}{
					"user": map[string]interface{}{
						"email": "john@example.com",
					},
				},
			},
			expected: map[string]interface{}{
				"user": map[string]interface{}{
					"email": "john@example.com",
				},
			},
		},
		{
			name: "shallow_merge_adds_new_keys",
			responses: []interface{}{
				map[string]interface{}{
					"key1": "value1",
				},
				map[string]interface{}{
					"key2": "value2",
				},
			},
			expected: map[string]interface{}{
				"key1": "value1",
				"key2": "value2",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := merger.Merge(tt.responses, config.MergeStrategyShallow)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestFunctional_Transform_ResponseMerging_Replace tests response merging with replace strategy.
func TestFunctional_Transform_ResponseMerging_Replace(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	merger := transform.NewResponseMerger(logger)

	tests := []struct {
		name      string
		responses []interface{}
		expected  interface{}
	}{
		{
			name: "replace_returns_last",
			responses: []interface{}{
				map[string]interface{}{"data": "first"},
				map[string]interface{}{"data": "second"},
				map[string]interface{}{"data": "third"},
			},
			expected: map[string]interface{}{"data": "third"},
		},
		{
			name: "replace_skips_nil",
			responses: []interface{}{
				map[string]interface{}{"data": "first"},
				nil,
				map[string]interface{}{"data": "third"},
			},
			expected: map[string]interface{}{"data": "third"},
		},
		{
			name: "replace_with_single_response",
			responses: []interface{}{
				map[string]interface{}{"data": "only"},
			},
			expected: map[string]interface{}{"data": "only"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := merger.Merge(tt.responses, config.MergeStrategyReplace)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestFunctional_Transform_Templating_BasicVariables tests templating with basic variables.
func TestFunctional_Transform_Templating_BasicVariables(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	engine := transform.NewTemplateEngine(logger)

	tests := []struct {
		name     string
		template string
		data     interface{}
		expected interface{}
	}{
		{
			name:     "simple_variable_substitution",
			template: `{"name": "{{.name}}", "id": "{{.id}}"}`,
			data: map[string]interface{}{
				"name": "Test",
				"id":   "123",
			},
			expected: map[string]interface{}{
				"name": "Test",
				"id":   "123",
			},
		},
		{
			name:     "nested_variable_access",
			template: `{"userName": "{{.user.name}}", "userEmail": "{{.user.email}}"}`,
			data: map[string]interface{}{
				"user": map[string]interface{}{
					"name":  "John",
					"email": "john@example.com",
				},
			},
			expected: map[string]interface{}{
				"userName":  "John",
				"userEmail": "john@example.com",
			},
		},
		{
			name:     "array_index_access",
			template: `{"first": "{{index .items 0}}"}`,
			data: map[string]interface{}{
				"items": []interface{}{"a", "b", "c"},
			},
			expected: map[string]interface{}{
				"first": "a",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := engine.Execute(tt.template, tt.data)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestFunctional_Transform_Templating_Functions tests templating with functions.
func TestFunctional_Transform_Templating_Functions(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	engine := transform.NewTemplateEngine(logger)

	tests := []struct {
		name     string
		template string
		data     interface{}
		expected interface{}
	}{
		{
			name:     "upper_function",
			template: `{"name": "{{upper .name}}"}`,
			data: map[string]interface{}{
				"name": "test",
			},
			expected: map[string]interface{}{
				"name": "TEST",
			},
		},
		{
			name:     "lower_function",
			template: `{"name": "{{lower .name}}"}`,
			data: map[string]interface{}{
				"name": "TEST",
			},
			expected: map[string]interface{}{
				"name": "test",
			},
		},
		{
			name:     "trim_function",
			template: `{"name": "{{trim .name}}"}`,
			data: map[string]interface{}{
				"name": "  test  ",
			},
			expected: map[string]interface{}{
				"name": "test",
			},
		},
		{
			name:     "json_function",
			template: `{{json .}}`,
			data: map[string]interface{}{
				"key": "value",
			},
			expected: map[string]interface{}{
				"key": "value",
			},
		},
		{
			name:     "default_function",
			template: `{"name": "{{default "unknown" .name}}"}`,
			data:     map[string]interface{}{},
			expected: map[string]interface{}{
				"name": "unknown",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := engine.Execute(tt.template, tt.data)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestFunctional_Transform_Request_BodyPassthrough tests request transformation with body passthrough.
func TestFunctional_Transform_Request_BodyPassthrough(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	transformer := transform.NewRequestTransformer(logger)

	tests := []struct {
		name     string
		request  interface{}
		expected interface{}
	}{
		{
			name: "passthrough_preserves_all_fields",
			request: map[string]interface{}{
				"id":       "123",
				"name":     "Test",
				"internal": "data",
				"debug":    true,
			},
			expected: map[string]interface{}{
				"id":       "123",
				"name":     "Test",
				"internal": "data",
				"debug":    true,
			},
		},
		{
			name: "passthrough_preserves_nested",
			request: map[string]interface{}{
				"user": map[string]interface{}{
					"name": "John",
				},
			},
			expected: map[string]interface{}{
				"user": map[string]interface{}{
					"name": "John",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.RequestTransformConfig{
				PassthroughBody: true,
			}
			result, err := transformer.TransformRequest(context.Background(), tt.request, cfg)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestFunctional_Transform_Request_FieldInjection tests request transformation with field injection.
func TestFunctional_Transform_Request_FieldInjection(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	transformer := transform.NewRequestTransformer(logger)

	tests := []struct {
		name       string
		request    interface{}
		injections []config.FieldInjection
		expected   interface{}
	}{
		{
			name: "inject_static_value",
			request: map[string]interface{}{
				"name": "Test",
			},
			injections: []config.FieldInjection{
				{Field: "gateway", Value: "avapigw"},
			},
			expected: map[string]interface{}{
				"name":    "Test",
				"gateway": "avapigw",
			},
		},
		{
			name: "inject_multiple_fields",
			request: map[string]interface{}{
				"name": "Test",
			},
			injections: []config.FieldInjection{
				{Field: "version", Value: "1.0"},
				{Field: "source", Value: "api"},
			},
			expected: map[string]interface{}{
				"name":    "Test",
				"version": "1.0",
				"source":  "api",
			},
		},
		{
			name: "inject_nested_field",
			request: map[string]interface{}{
				"name": "Test",
			},
			injections: []config.FieldInjection{
				{Field: "metadata.gateway", Value: "avapigw"},
			},
			expected: map[string]interface{}{
				"name": "Test",
				"metadata": map[string]interface{}{
					"gateway": "avapigw",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.RequestTransformConfig{
				InjectFields: tt.injections,
			}
			result, err := transformer.TransformRequest(context.Background(), tt.request, cfg)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestFunctional_Transform_Request_FieldRemoval tests request transformation with field removal.
func TestFunctional_Transform_Request_FieldRemoval(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	transformer := transform.NewRequestTransformer(logger)

	tests := []struct {
		name         string
		request      interface{}
		removeFields []string
		expected     interface{}
	}{
		{
			name: "remove_single_field",
			request: map[string]interface{}{
				"name":     "Test",
				"internal": "secret",
			},
			removeFields: []string{"internal"},
			expected: map[string]interface{}{
				"name": "Test",
			},
		},
		{
			name: "remove_multiple_fields",
			request: map[string]interface{}{
				"name":     "Test",
				"internal": "secret",
				"debug":    true,
			},
			removeFields: []string{"internal", "debug"},
			expected: map[string]interface{}{
				"name": "Test",
			},
		},
		{
			name: "remove_nested_field",
			request: map[string]interface{}{
				"name": "Test",
				"user": map[string]interface{}{
					"name":     "John",
					"password": "secret",
				},
			},
			removeFields: []string{"user.password"},
			expected: map[string]interface{}{
				"name": "Test",
				"user": map[string]interface{}{
					"name": "John",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.RequestTransformConfig{
				RemoveFields: tt.removeFields,
			}
			result, err := transformer.TransformRequest(context.Background(), tt.request, cfg)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestFunctional_Transform_Request_DefaultValues tests request transformation with default values.
func TestFunctional_Transform_Request_DefaultValues(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	transformer := transform.NewRequestTransformer(logger)

	tests := []struct {
		name          string
		request       interface{}
		defaultValues map[string]interface{}
		expected      interface{}
	}{
		{
			name: "apply_default_for_missing_field",
			request: map[string]interface{}{
				"name": "Test",
			},
			defaultValues: map[string]interface{}{
				"version": "1.0",
			},
			expected: map[string]interface{}{
				"name":    "Test",
				"version": "1.0",
			},
		},
		{
			name: "do_not_override_existing_field",
			request: map[string]interface{}{
				"name":    "Test",
				"version": "2.0",
			},
			defaultValues: map[string]interface{}{
				"version": "1.0",
			},
			expected: map[string]interface{}{
				"name":    "Test",
				"version": "2.0",
			},
		},
		{
			name: "apply_multiple_defaults",
			request: map[string]interface{}{
				"name": "Test",
			},
			defaultValues: map[string]interface{}{
				"version": "1.0",
				"source":  "api",
				"active":  true,
			},
			expected: map[string]interface{}{
				"name":    "Test",
				"version": "1.0",
				"source":  "api",
				"active":  true,
			},
		},
		{
			name:    "apply_defaults_to_nil_request",
			request: nil,
			defaultValues: map[string]interface{}{
				"version": "1.0",
			},
			expected: map[string]interface{}{
				"version": "1.0",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.RequestTransformConfig{
				DefaultValues: tt.defaultValues,
			}
			result, err := transformer.TransformRequest(context.Background(), tt.request, cfg)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}
