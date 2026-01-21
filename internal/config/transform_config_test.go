// Package config provides configuration types and loading for the API Gateway.
package config

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestTransformConfig_IsEmpty(t *testing.T) {
	tests := []struct {
		name     string
		config   *TransformConfig
		expected bool
	}{
		{
			name:     "nil config",
			config:   nil,
			expected: true,
		},
		{
			name:     "empty config",
			config:   &TransformConfig{},
			expected: true,
		},
		{
			name: "config with request",
			config: &TransformConfig{
				Request: &RequestTransformConfig{
					PassthroughBody: true,
				},
			},
			expected: false,
		},
		{
			name: "config with response",
			config: &TransformConfig{
				Response: &ResponseTransformConfig{
					AllowFields: []string{"name"},
				},
			},
			expected: false,
		},
		{
			name: "config with both",
			config: &TransformConfig{
				Request: &RequestTransformConfig{
					BodyTemplate: "test",
				},
				Response: &ResponseTransformConfig{
					DenyFields: []string{"password"},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.IsEmpty()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRequestTransformConfig_IsEmpty(t *testing.T) {
	tests := []struct {
		name     string
		config   *RequestTransformConfig
		expected bool
	}{
		{
			name:     "nil config",
			config:   nil,
			expected: true,
		},
		{
			name:     "empty config",
			config:   &RequestTransformConfig{},
			expected: true,
		},
		{
			name: "config with passthrough body",
			config: &RequestTransformConfig{
				PassthroughBody: true,
			},
			expected: false,
		},
		{
			name: "config with body template",
			config: &RequestTransformConfig{
				BodyTemplate: "{{.name}}",
			},
			expected: false,
		},
		{
			name: "config with static headers",
			config: &RequestTransformConfig{
				StaticHeaders: map[string]string{"X-Custom": "value"},
			},
			expected: false,
		},
		{
			name: "config with dynamic headers",
			config: &RequestTransformConfig{
				DynamicHeaders: []DynamicHeader{{Name: "X-User", Source: "jwt.claim.sub"}},
			},
			expected: false,
		},
		{
			name: "config with inject fields",
			config: &RequestTransformConfig{
				InjectFields: []FieldInjection{{Field: "user_id", Source: "jwt.claim.sub"}},
			},
			expected: false,
		},
		{
			name: "config with remove fields",
			config: &RequestTransformConfig{
				RemoveFields: []string{"internal"},
			},
			expected: false,
		},
		{
			name: "config with default values",
			config: &RequestTransformConfig{
				DefaultValues: map[string]interface{}{"status": "active"},
			},
			expected: false,
		},
		{
			name: "config with validate before transform",
			config: &RequestTransformConfig{
				ValidateBeforeTransform: true,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.IsEmpty()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestResponseTransformConfig_IsEmpty(t *testing.T) {
	tests := []struct {
		name     string
		config   *ResponseTransformConfig
		expected bool
	}{
		{
			name:     "nil config",
			config:   nil,
			expected: true,
		},
		{
			name:     "empty config",
			config:   &ResponseTransformConfig{},
			expected: true,
		},
		{
			name: "config with allow fields",
			config: &ResponseTransformConfig{
				AllowFields: []string{"name", "email"},
			},
			expected: false,
		},
		{
			name: "config with deny fields",
			config: &ResponseTransformConfig{
				DenyFields: []string{"password", "secret"},
			},
			expected: false,
		},
		{
			name: "config with field mappings",
			config: &ResponseTransformConfig{
				FieldMappings: []FieldMapping{{Source: "old_name", Target: "new_name"}},
			},
			expected: false,
		},
		{
			name: "config with group fields",
			config: &ResponseTransformConfig{
				GroupFields: []FieldGroup{{Name: "user", Fields: []string{"name", "email"}}},
			},
			expected: false,
		},
		{
			name: "config with flatten fields",
			config: &ResponseTransformConfig{
				FlattenFields: []string{"metadata"},
			},
			expected: false,
		},
		{
			name: "config with array operations",
			config: &ResponseTransformConfig{
				ArrayOperations: []ArrayOperation{{Field: "items", Operation: "limit", Value: 10}},
			},
			expected: false,
		},
		{
			name: "config with template",
			config: &ResponseTransformConfig{
				Template: `{"result": {{.data}}}`,
			},
			expected: false,
		},
		{
			name: "config with merge strategy",
			config: &ResponseTransformConfig{
				MergeStrategy: MergeStrategyDeep,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.IsEmpty()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestTransformConfig_YAMLMarshalUnmarshal(t *testing.T) {
	original := &TransformConfig{
		Request: &RequestTransformConfig{
			PassthroughBody: false,
			BodyTemplate:    `{"user": "{{.name}}"}`,
			StaticHeaders:   map[string]string{"X-API-Key": "secret"},
			DynamicHeaders: []DynamicHeader{
				{Name: "X-User-ID", Source: "jwt.claim.sub"},
			},
			InjectFields: []FieldInjection{
				{Field: "timestamp", Value: "now"},
			},
			RemoveFields:  []string{"internal_id"},
			DefaultValues: map[string]interface{}{"status": "pending"},
		},
		Response: &ResponseTransformConfig{
			AllowFields: []string{"id", "name", "email"},
			DenyFields:  []string{"password"},
			FieldMappings: []FieldMapping{
				{Source: "user_name", Target: "username"},
			},
			GroupFields: []FieldGroup{
				{Name: "contact", Fields: []string{"email", "phone"}},
			},
			FlattenFields: []string{"metadata"},
			ArrayOperations: []ArrayOperation{
				{Field: "items", Operation: ArrayOperationLimit, Value: 10},
			},
			MergeStrategy: MergeStrategyDeep,
		},
	}

	// Marshal to YAML
	data, err := yaml.Marshal(original)
	require.NoError(t, err)

	// Unmarshal back
	var result TransformConfig
	err = yaml.Unmarshal(data, &result)
	require.NoError(t, err)

	// Verify
	assert.Equal(t, original.Request.PassthroughBody, result.Request.PassthroughBody)
	assert.Equal(t, original.Request.BodyTemplate, result.Request.BodyTemplate)
	assert.Equal(t, original.Request.StaticHeaders, result.Request.StaticHeaders)
	assert.Equal(t, original.Request.DynamicHeaders, result.Request.DynamicHeaders)
	assert.Equal(t, original.Request.RemoveFields, result.Request.RemoveFields)
	assert.Equal(t, original.Response.AllowFields, result.Response.AllowFields)
	assert.Equal(t, original.Response.DenyFields, result.Response.DenyFields)
	assert.Equal(t, original.Response.FieldMappings, result.Response.FieldMappings)
	assert.Equal(t, original.Response.MergeStrategy, result.Response.MergeStrategy)
}

func TestTransformConfig_JSONMarshalUnmarshal(t *testing.T) {
	original := &TransformConfig{
		Request: &RequestTransformConfig{
			BodyTemplate:  `{"data": "{{.input}}"}`,
			StaticHeaders: map[string]string{"Content-Type": "application/json"},
		},
		Response: &ResponseTransformConfig{
			AllowFields:   []string{"result"},
			MergeStrategy: MergeStrategyShallow,
		},
	}

	// Marshal to JSON
	data, err := json.Marshal(original)
	require.NoError(t, err)

	// Unmarshal back
	var result TransformConfig
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	// Verify
	assert.Equal(t, original.Request.BodyTemplate, result.Request.BodyTemplate)
	assert.Equal(t, original.Request.StaticHeaders, result.Request.StaticHeaders)
	assert.Equal(t, original.Response.AllowFields, result.Response.AllowFields)
	assert.Equal(t, original.Response.MergeStrategy, result.Response.MergeStrategy)
}

func TestMergeStrategyConstants(t *testing.T) {
	assert.Equal(t, "deep", MergeStrategyDeep)
	assert.Equal(t, "shallow", MergeStrategyShallow)
	assert.Equal(t, "replace", MergeStrategyReplace)
}

func TestArrayOperationConstants(t *testing.T) {
	assert.Equal(t, "append", ArrayOperationAppend)
	assert.Equal(t, "prepend", ArrayOperationPrepend)
	assert.Equal(t, "filter", ArrayOperationFilter)
	assert.Equal(t, "sort", ArrayOperationSort)
	assert.Equal(t, "limit", ArrayOperationLimit)
	assert.Equal(t, "deduplicate", ArrayOperationDeduplicate)
}

func TestFieldMapping_Struct(t *testing.T) {
	mapping := FieldMapping{
		Source: "old_field",
		Target: "new_field",
	}

	assert.Equal(t, "old_field", mapping.Source)
	assert.Equal(t, "new_field", mapping.Target)
}

func TestFieldGroup_Struct(t *testing.T) {
	group := FieldGroup{
		Name:   "contact_info",
		Fields: []string{"email", "phone", "address"},
	}

	assert.Equal(t, "contact_info", group.Name)
	assert.Len(t, group.Fields, 3)
	assert.Contains(t, group.Fields, "email")
}

func TestArrayOperation_Struct(t *testing.T) {
	tests := []struct {
		name      string
		operation ArrayOperation
	}{
		{
			name: "append operation",
			operation: ArrayOperation{
				Field:     "items",
				Operation: ArrayOperationAppend,
				Value:     "new_item",
			},
		},
		{
			name: "filter operation",
			operation: ArrayOperation{
				Field:     "users",
				Operation: ArrayOperationFilter,
				Condition: "item.active == true",
			},
		},
		{
			name: "limit operation",
			operation: ArrayOperation{
				Field:     "results",
				Operation: ArrayOperationLimit,
				Value:     10,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotEmpty(t, tt.operation.Field)
			assert.NotEmpty(t, tt.operation.Operation)
		})
	}
}

func TestDynamicHeader_Struct(t *testing.T) {
	header := DynamicHeader{
		Name:   "X-User-ID",
		Source: "jwt.claim.sub",
	}

	assert.Equal(t, "X-User-ID", header.Name)
	assert.Equal(t, "jwt.claim.sub", header.Source)
}

func TestFieldInjection_Struct(t *testing.T) {
	tests := []struct {
		name      string
		injection FieldInjection
	}{
		{
			name: "static value injection",
			injection: FieldInjection{
				Field: "version",
				Value: "1.0",
			},
		},
		{
			name: "dynamic source injection",
			injection: FieldInjection{
				Field:  "user_id",
				Source: "jwt.claim.sub",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotEmpty(t, tt.injection.Field)
		})
	}
}
