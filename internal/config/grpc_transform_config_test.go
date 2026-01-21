// Package config provides configuration types and loading for the API Gateway.
package config

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestGRPCTransformConfig_IsEmpty(t *testing.T) {
	tests := []struct {
		name     string
		config   *GRPCTransformConfig
		expected bool
	}{
		{
			name:     "nil config",
			config:   nil,
			expected: true,
		},
		{
			name:     "empty config",
			config:   &GRPCTransformConfig{},
			expected: true,
		},
		{
			name: "config with request",
			config: &GRPCTransformConfig{
				Request: &GRPCRequestTransformConfig{
					InjectFieldMask: []string{"user.name"},
				},
			},
			expected: false,
		},
		{
			name: "config with response",
			config: &GRPCTransformConfig{
				Response: &GRPCResponseTransformConfig{
					FieldMask: []string{"user.name", "user.email"},
				},
			},
			expected: false,
		},
		{
			name: "config with both",
			config: &GRPCTransformConfig{
				Request: &GRPCRequestTransformConfig{
					StaticMetadata: map[string]string{"x-api-key": "secret"},
				},
				Response: &GRPCResponseTransformConfig{
					PreserveUnknownFields: true,
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

func TestGRPCRequestTransformConfig_IsEmpty(t *testing.T) {
	tests := []struct {
		name     string
		config   *GRPCRequestTransformConfig
		expected bool
	}{
		{
			name:     "nil config",
			config:   nil,
			expected: true,
		},
		{
			name:     "empty config",
			config:   &GRPCRequestTransformConfig{},
			expected: true,
		},
		{
			name: "config with inject field mask",
			config: &GRPCRequestTransformConfig{
				InjectFieldMask: []string{"user.name"},
			},
			expected: false,
		},
		{
			name: "config with static metadata",
			config: &GRPCRequestTransformConfig{
				StaticMetadata: map[string]string{"x-api-key": "secret"},
			},
			expected: false,
		},
		{
			name: "config with dynamic metadata",
			config: &GRPCRequestTransformConfig{
				DynamicMetadata: []DynamicMetadata{{Key: "x-user-id", Source: "jwt.claim.sub"}},
			},
			expected: false,
		},
		{
			name: "config with inject fields",
			config: &GRPCRequestTransformConfig{
				InjectFields: []FieldInjection{{Field: "user_id", Source: "jwt.claim.sub"}},
			},
			expected: false,
		},
		{
			name: "config with remove fields",
			config: &GRPCRequestTransformConfig{
				RemoveFields: []string{"internal"},
			},
			expected: false,
		},
		{
			name: "config with default values",
			config: &GRPCRequestTransformConfig{
				DefaultValues: map[string]interface{}{"status": "active"},
			},
			expected: false,
		},
		{
			name: "config with validate before transform",
			config: &GRPCRequestTransformConfig{
				ValidateBeforeTransform: true,
			},
			expected: false,
		},
		{
			name: "config with inject deadline",
			config: &GRPCRequestTransformConfig{
				InjectDeadline: Duration(5 * time.Second),
			},
			expected: false,
		},
		{
			name: "config with authority override",
			config: &GRPCRequestTransformConfig{
				AuthorityOverride: "api.example.com",
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

func TestGRPCResponseTransformConfig_IsEmpty(t *testing.T) {
	tests := []struct {
		name     string
		config   *GRPCResponseTransformConfig
		expected bool
	}{
		{
			name:     "nil config",
			config:   nil,
			expected: true,
		},
		{
			name:     "empty config",
			config:   &GRPCResponseTransformConfig{},
			expected: true,
		},
		{
			name: "config with field mask",
			config: &GRPCResponseTransformConfig{
				FieldMask: []string{"user.name", "user.email"},
			},
			expected: false,
		},
		{
			name: "config with field mappings",
			config: &GRPCResponseTransformConfig{
				FieldMappings: []FieldMapping{{Source: "old_name", Target: "new_name"}},
			},
			expected: false,
		},
		{
			name: "config with repeated field ops",
			config: &GRPCResponseTransformConfig{
				RepeatedFieldOps: []RepeatedFieldOperation{{Field: "items", Operation: "limit", Limit: 10}},
			},
			expected: false,
		},
		{
			name: "config with map field ops",
			config: &GRPCResponseTransformConfig{
				MapFieldOps: []MapFieldOperation{{Field: "metadata", Operation: "filterKeys", AllowKeys: []string{"key1"}}},
			},
			expected: false,
		},
		{
			name: "config with preserve unknown fields",
			config: &GRPCResponseTransformConfig{
				PreserveUnknownFields: true,
			},
			expected: false,
		},
		{
			name: "config with streaming config",
			config: &GRPCResponseTransformConfig{
				StreamingConfig: &StreamingTransformConfig{
					PerMessageTransform: true,
				},
			},
			expected: false,
		},
		{
			name: "config with trailer metadata",
			config: &GRPCResponseTransformConfig{
				TrailerMetadata: map[string]string{"x-request-id": "123"},
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

func TestStreamingTransformConfig_IsEmpty(t *testing.T) {
	tests := []struct {
		name     string
		config   *StreamingTransformConfig
		expected bool
	}{
		{
			name:     "nil config",
			config:   nil,
			expected: true,
		},
		{
			name:     "empty config",
			config:   &StreamingTransformConfig{},
			expected: true,
		},
		{
			name: "config with per message transform",
			config: &StreamingTransformConfig{
				PerMessageTransform: true,
			},
			expected: false,
		},
		{
			name: "config with aggregate",
			config: &StreamingTransformConfig{
				Aggregate: true,
			},
			expected: false,
		},
		{
			name: "config with filter condition",
			config: &StreamingTransformConfig{
				FilterCondition: "msg.type == 'data'",
			},
			expected: false,
		},
		{
			name: "config with buffer size",
			config: &StreamingTransformConfig{
				BufferSize: 100,
			},
			expected: false,
		},
		{
			name: "config with rate limit",
			config: &StreamingTransformConfig{
				RateLimit: 1000,
			},
			expected: false,
		},
		{
			name: "config with message timeout",
			config: &StreamingTransformConfig{
				MessageTimeout: Duration(5 * time.Second),
			},
			expected: false,
		},
		{
			name: "config with total timeout",
			config: &StreamingTransformConfig{
				TotalTimeout: Duration(60 * time.Second),
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

func TestGRPCTransformConfig_YAMLMarshalUnmarshal(t *testing.T) {
	original := &GRPCTransformConfig{
		Request: &GRPCRequestTransformConfig{
			InjectFieldMask: []string{"user.name", "user.email"},
			StaticMetadata:  map[string]string{"x-api-key": "secret"},
			DynamicMetadata: []DynamicMetadata{
				{Key: "x-user-id", Source: "jwt.claim.sub"},
			},
			InjectFields: []FieldInjection{
				{Field: "timestamp", Value: "now"},
			},
			RemoveFields:            []string{"internal_id"},
			DefaultValues:           map[string]interface{}{"status": "pending"},
			ValidateBeforeTransform: true,
			AuthorityOverride:       "api.example.com",
		},
		Response: &GRPCResponseTransformConfig{
			FieldMask: []string{"user.name", "user.email", "items"},
			FieldMappings: []FieldMapping{
				{Source: "user_name", Target: "username"},
			},
			RepeatedFieldOps: []RepeatedFieldOperation{
				{Field: "items", Operation: RepeatedFieldOpLimit, Limit: 10},
				{Field: "users", Operation: RepeatedFieldOpSort, SortField: "name", SortOrder: SortOrderAsc},
			},
			MapFieldOps: []MapFieldOperation{
				{Field: "metadata", Operation: MapFieldOpFilterKeys, AllowKeys: []string{"key1", "key2"}},
			},
			PreserveUnknownFields: true,
			StreamingConfig: &StreamingTransformConfig{
				PerMessageTransform: true,
				BufferSize:          100,
				RateLimit:           1000,
			},
			TrailerMetadata: map[string]string{"x-request-id": "123"},
		},
	}

	// Marshal to YAML
	data, err := yaml.Marshal(original)
	require.NoError(t, err)

	// Unmarshal back
	var result GRPCTransformConfig
	err = yaml.Unmarshal(data, &result)
	require.NoError(t, err)

	// Verify request config
	assert.Equal(t, original.Request.InjectFieldMask, result.Request.InjectFieldMask)
	assert.Equal(t, original.Request.StaticMetadata, result.Request.StaticMetadata)
	assert.Equal(t, original.Request.DynamicMetadata, result.Request.DynamicMetadata)
	assert.Equal(t, original.Request.RemoveFields, result.Request.RemoveFields)
	assert.Equal(t, original.Request.ValidateBeforeTransform, result.Request.ValidateBeforeTransform)
	assert.Equal(t, original.Request.AuthorityOverride, result.Request.AuthorityOverride)

	// Verify response config
	assert.Equal(t, original.Response.FieldMask, result.Response.FieldMask)
	assert.Equal(t, original.Response.FieldMappings, result.Response.FieldMappings)
	assert.Equal(t, original.Response.PreserveUnknownFields, result.Response.PreserveUnknownFields)
	assert.Equal(t, original.Response.TrailerMetadata, result.Response.TrailerMetadata)
}

func TestGRPCTransformConfig_JSONMarshalUnmarshal(t *testing.T) {
	original := &GRPCTransformConfig{
		Request: &GRPCRequestTransformConfig{
			InjectFieldMask: []string{"user.name"},
			StaticMetadata:  map[string]string{"x-api-key": "secret"},
		},
		Response: &GRPCResponseTransformConfig{
			FieldMask:             []string{"user.name", "user.email"},
			PreserveUnknownFields: true,
		},
	}

	// Marshal to JSON
	data, err := json.Marshal(original)
	require.NoError(t, err)

	// Unmarshal back
	var result GRPCTransformConfig
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	// Verify
	assert.Equal(t, original.Request.InjectFieldMask, result.Request.InjectFieldMask)
	assert.Equal(t, original.Request.StaticMetadata, result.Request.StaticMetadata)
	assert.Equal(t, original.Response.FieldMask, result.Response.FieldMask)
	assert.Equal(t, original.Response.PreserveUnknownFields, result.Response.PreserveUnknownFields)
}

func TestRepeatedFieldOperationConstants(t *testing.T) {
	assert.Equal(t, "filter", RepeatedFieldOpFilter)
	assert.Equal(t, "sort", RepeatedFieldOpSort)
	assert.Equal(t, "limit", RepeatedFieldOpLimit)
	assert.Equal(t, "deduplicate", RepeatedFieldOpDeduplicate)
}

func TestMapFieldOperationConstants(t *testing.T) {
	assert.Equal(t, "filterKeys", MapFieldOpFilterKeys)
	assert.Equal(t, "merge", MapFieldOpMerge)
}

func TestSortOrderConstants(t *testing.T) {
	assert.Equal(t, "asc", SortOrderAsc)
	assert.Equal(t, "desc", SortOrderDesc)
}

func TestRepeatedFieldOperation_Struct(t *testing.T) {
	tests := []struct {
		name      string
		operation RepeatedFieldOperation
	}{
		{
			name: "filter operation",
			operation: RepeatedFieldOperation{
				Field:     "items",
				Operation: RepeatedFieldOpFilter,
				Condition: "item.active == true",
			},
		},
		{
			name: "sort operation",
			operation: RepeatedFieldOperation{
				Field:     "users",
				Operation: RepeatedFieldOpSort,
				SortField: "name",
				SortOrder: SortOrderAsc,
			},
		},
		{
			name: "limit operation",
			operation: RepeatedFieldOperation{
				Field:     "results",
				Operation: RepeatedFieldOpLimit,
				Limit:     10,
			},
		},
		{
			name: "deduplicate operation",
			operation: RepeatedFieldOperation{
				Field:     "tags",
				Operation: RepeatedFieldOpDeduplicate,
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

func TestMapFieldOperation_Struct(t *testing.T) {
	tests := []struct {
		name      string
		operation MapFieldOperation
	}{
		{
			name: "filter keys with allow list",
			operation: MapFieldOperation{
				Field:     "metadata",
				Operation: MapFieldOpFilterKeys,
				AllowKeys: []string{"key1", "key2"},
			},
		},
		{
			name: "filter keys with deny list",
			operation: MapFieldOperation{
				Field:     "metadata",
				Operation: MapFieldOpFilterKeys,
				DenyKeys:  []string{"secret", "internal"},
			},
		},
		{
			name: "merge operation",
			operation: MapFieldOperation{
				Field:     "config",
				Operation: MapFieldOpMerge,
				MergeWith: map[string]interface{}{"new_key": "new_value"},
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

func TestDynamicMetadata_Struct(t *testing.T) {
	metadata := DynamicMetadata{
		Key:    "x-user-id",
		Source: "jwt.claim.sub",
	}

	assert.Equal(t, "x-user-id", metadata.Key)
	assert.Equal(t, "jwt.claim.sub", metadata.Source)
}

func TestStreamingTransformConfig_Struct(t *testing.T) {
	config := StreamingTransformConfig{
		PerMessageTransform: true,
		Aggregate:           false,
		FilterCondition:     "msg.type == 'data'",
		BufferSize:          100,
		RateLimit:           1000,
		MessageTimeout:      Duration(5 * time.Second),
		TotalTimeout:        Duration(60 * time.Second),
	}

	assert.True(t, config.PerMessageTransform)
	assert.False(t, config.Aggregate)
	assert.Equal(t, "msg.type == 'data'", config.FilterCondition)
	assert.Equal(t, 100, config.BufferSize)
	assert.Equal(t, 1000, config.RateLimit)
	assert.Equal(t, Duration(5*time.Second), config.MessageTimeout)
	assert.Equal(t, Duration(60*time.Second), config.TotalTimeout)
}
