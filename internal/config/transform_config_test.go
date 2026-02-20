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

func TestResponseTransformConfig_UnmarshalJSON_CRDMapFormat(t *testing.T) {
	// CRD sends fieldMappings as map[string]string.
	input := `{
		"allowFields": ["id", "name"],
		"denyFields": ["password"],
		"fieldMappings": {
			"created_at": "createdAt",
			"user_name": "userName"
		},
		"template": "{{.data}}",
		"mergeStrategy": "deep"
	}`

	var rtc ResponseTransformConfig
	err := json.Unmarshal([]byte(input), &rtc)
	require.NoError(t, err)

	assert.Equal(t, []string{"id", "name"}, rtc.AllowFields)
	assert.Equal(t, []string{"password"}, rtc.DenyFields)
	assert.Equal(t, "{{.data}}", rtc.Template)
	assert.Equal(t, "deep", rtc.MergeStrategy)

	// FieldMappings should be converted from map and sorted by Source.
	require.Len(t, rtc.FieldMappings, 2)
	assert.Equal(t, FieldMapping{Source: "created_at", Target: "createdAt"}, rtc.FieldMappings[0])
	assert.Equal(t, FieldMapping{Source: "user_name", Target: "userName"}, rtc.FieldMappings[1])
}

func TestResponseTransformConfig_UnmarshalJSON_InternalArrayFormat(t *testing.T) {
	// Internal format uses []FieldMapping with source/target objects.
	input := `{
		"allowFields": ["id"],
		"fieldMappings": [
			{"source": "old_name", "target": "new_name"},
			{"source": "created_at", "target": "createdAt"}
		],
		"mergeStrategy": "shallow"
	}`

	var rtc ResponseTransformConfig
	err := json.Unmarshal([]byte(input), &rtc)
	require.NoError(t, err)

	assert.Equal(t, []string{"id"}, rtc.AllowFields)
	assert.Equal(t, "shallow", rtc.MergeStrategy)

	require.Len(t, rtc.FieldMappings, 2)
	assert.Equal(t, FieldMapping{Source: "old_name", Target: "new_name"}, rtc.FieldMappings[0])
	assert.Equal(t, FieldMapping{Source: "created_at", Target: "createdAt"}, rtc.FieldMappings[1])
}

func TestResponseTransformConfig_UnmarshalJSON_EmptyFieldMappings(t *testing.T) {
	input := `{
		"allowFields": ["id"],
		"fieldMappings": {}
	}`

	var rtc ResponseTransformConfig
	err := json.Unmarshal([]byte(input), &rtc)
	require.NoError(t, err)

	assert.Equal(t, []string{"id"}, rtc.AllowFields)
	assert.Empty(t, rtc.FieldMappings)
}

func TestResponseTransformConfig_UnmarshalJSON_NoFieldMappings(t *testing.T) {
	input := `{
		"allowFields": ["id", "name"],
		"denyFields": ["secret"]
	}`

	var rtc ResponseTransformConfig
	err := json.Unmarshal([]byte(input), &rtc)
	require.NoError(t, err)

	assert.Equal(t, []string{"id", "name"}, rtc.AllowFields)
	assert.Equal(t, []string{"secret"}, rtc.DenyFields)
	assert.Empty(t, rtc.FieldMappings)
}

func TestResponseTransformConfig_UnmarshalJSON_InvalidJSON(t *testing.T) {
	input := `{invalid json}`

	var rtc ResponseTransformConfig
	err := json.Unmarshal([]byte(input), &rtc)
	assert.Error(t, err)
}

func TestResponseTransformConfig_UnmarshalJSON_MapSortOrder(t *testing.T) {
	// Verify deterministic sort order with multiple entries.
	input := `{
		"fieldMappings": {
			"zebra": "z",
			"alpha": "a",
			"middle": "m",
			"beta": "b"
		}
	}`

	var rtc ResponseTransformConfig
	err := json.Unmarshal([]byte(input), &rtc)
	require.NoError(t, err)

	require.Len(t, rtc.FieldMappings, 4)
	assert.Equal(t, "alpha", rtc.FieldMappings[0].Source)
	assert.Equal(t, "beta", rtc.FieldMappings[1].Source)
	assert.Equal(t, "middle", rtc.FieldMappings[2].Source)
	assert.Equal(t, "zebra", rtc.FieldMappings[3].Source)
}

func TestRequestTransformConfig_UnmarshalJSON_CRDTemplateKey(t *testing.T) {
	// CRD sends "template" instead of "bodyTemplate".
	input := `{
		"template": "{\"wrapped\": {{.Body}}}",
		"staticHeaders": {"X-Custom": "value"}
	}`

	var rtc RequestTransformConfig
	err := json.Unmarshal([]byte(input), &rtc)
	require.NoError(t, err)

	assert.Equal(t, `{"wrapped": {{.Body}}}`, rtc.BodyTemplate)
	assert.Equal(t, map[string]string{"X-Custom": "value"}, rtc.StaticHeaders)
}

func TestRequestTransformConfig_UnmarshalJSON_InternalBodyTemplateKey(t *testing.T) {
	// Internal format uses "bodyTemplate".
	input := `{
		"bodyTemplate": "{\"data\": {{.input}}}",
		"passthroughBody": true
	}`

	var rtc RequestTransformConfig
	err := json.Unmarshal([]byte(input), &rtc)
	require.NoError(t, err)

	assert.Equal(t, `{"data": {{.input}}}`, rtc.BodyTemplate)
	assert.True(t, rtc.PassthroughBody)
}

func TestRequestTransformConfig_UnmarshalJSON_BodyTemplateTakesPrecedence(t *testing.T) {
	// If both "bodyTemplate" and "template" are present, bodyTemplate takes precedence.
	input := `{
		"bodyTemplate": "from_bodyTemplate",
		"template": "from_template"
	}`

	var rtc RequestTransformConfig
	err := json.Unmarshal([]byte(input), &rtc)
	require.NoError(t, err)

	assert.Equal(t, "from_bodyTemplate", rtc.BodyTemplate)
}

func TestRequestTransformConfig_UnmarshalJSON_NoTemplate(t *testing.T) {
	input := `{
		"passthroughBody": true,
		"staticHeaders": {"Content-Type": "application/json"}
	}`

	var rtc RequestTransformConfig
	err := json.Unmarshal([]byte(input), &rtc)
	require.NoError(t, err)

	assert.True(t, rtc.PassthroughBody)
	assert.Empty(t, rtc.BodyTemplate)
	assert.Equal(t, map[string]string{"Content-Type": "application/json"}, rtc.StaticHeaders)
}

func TestRequestTransformConfig_UnmarshalJSON_InvalidJSON(t *testing.T) {
	input := `{invalid}`

	var rtc RequestTransformConfig
	err := json.Unmarshal([]byte(input), &rtc)
	assert.Error(t, err)
}

func TestTransformConfig_UnmarshalJSON_FullCRDFormat(t *testing.T) {
	// Simulate the full CRD JSON that the operator sends.
	input := `{
		"request": {
			"template": "{\"user\": \"{{.name}}\"}"
		},
		"response": {
			"allowFields": ["id", "name", "email"],
			"denyFields": ["password"],
			"fieldMappings": {
				"created_at": "createdAt",
				"user_name": "userName"
			}
		}
	}`

	var tc TransformConfig
	err := json.Unmarshal([]byte(input), &tc)
	require.NoError(t, err)

	require.NotNil(t, tc.Request)
	assert.Equal(t, `{"user": "{{.name}}"}`, tc.Request.BodyTemplate)

	require.NotNil(t, tc.Response)
	assert.Equal(t, []string{"id", "name", "email"}, tc.Response.AllowFields)
	assert.Equal(t, []string{"password"}, tc.Response.DenyFields)
	require.Len(t, tc.Response.FieldMappings, 2)
	assert.Equal(t, FieldMapping{Source: "created_at", Target: "createdAt"}, tc.Response.FieldMappings[0])
	assert.Equal(t, FieldMapping{Source: "user_name", Target: "userName"}, tc.Response.FieldMappings[1])
}

func TestTransformConfig_UnmarshalJSON_FullInternalFormat(t *testing.T) {
	// Internal format with bodyTemplate and []FieldMapping.
	input := `{
		"request": {
			"bodyTemplate": "{\"data\": \"{{.input}}\"}",
			"staticHeaders": {"Content-Type": "application/json"}
		},
		"response": {
			"allowFields": ["result"],
			"fieldMappings": [
				{"source": "old_name", "target": "new_name"}
			],
			"mergeStrategy": "shallow"
		}
	}`

	var tc TransformConfig
	err := json.Unmarshal([]byte(input), &tc)
	require.NoError(t, err)

	require.NotNil(t, tc.Request)
	assert.Equal(t, `{"data": "{{.input}}"}`, tc.Request.BodyTemplate)
	assert.Equal(t, map[string]string{"Content-Type": "application/json"}, tc.Request.StaticHeaders)

	require.NotNil(t, tc.Response)
	assert.Equal(t, []string{"result"}, tc.Response.AllowFields)
	assert.Equal(t, "shallow", tc.Response.MergeStrategy)
	require.Len(t, tc.Response.FieldMappings, 1)
	assert.Equal(t, FieldMapping{Source: "old_name", Target: "new_name"}, tc.Response.FieldMappings[0])
}

func TestResponseTransformConfig_UnmarshalJSON_WithArrayOperations(t *testing.T) {
	// CRD format with fieldMappings as map and array operations.
	input := `{
		"fieldMappings": {
			"old_field": "new_field"
		},
		"arrayOperations": [
			{"field": "items", "operation": "limit", "value": 10}
		],
		"flattenFields": ["metadata"],
		"groupFields": [
			{"name": "contact", "fields": ["email", "phone"]}
		]
	}`

	var rtc ResponseTransformConfig
	err := json.Unmarshal([]byte(input), &rtc)
	require.NoError(t, err)

	require.Len(t, rtc.FieldMappings, 1)
	assert.Equal(t, FieldMapping{Source: "old_field", Target: "new_field"}, rtc.FieldMappings[0])

	require.Len(t, rtc.ArrayOperations, 1)
	assert.Equal(t, "items", rtc.ArrayOperations[0].Field)
	assert.Equal(t, "limit", rtc.ArrayOperations[0].Operation)

	assert.Equal(t, []string{"metadata"}, rtc.FlattenFields)

	require.Len(t, rtc.GroupFields, 1)
	assert.Equal(t, "contact", rtc.GroupFields[0].Name)
	assert.Equal(t, []string{"email", "phone"}, rtc.GroupFields[0].Fields)
}
