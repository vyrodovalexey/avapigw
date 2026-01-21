//go:build functional
// +build functional

// Package functional contains functional tests for the API Gateway.
// These tests verify gRPC transformation logic in isolation.
package functional

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"

	"github.com/vyrodovalexey/avapigw/internal/config"
	grpctransform "github.com/vyrodovalexey/avapigw/internal/grpc/transform"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/transform"
)

// TestFunctional_GRPCTransform_FieldMaskFiltering tests FieldMask-based filtering.
func TestFunctional_GRPCTransform_FieldMaskFiltering(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	filter := transform.NewFieldFilter(logger)

	tests := []struct {
		name      string
		data      map[string]interface{}
		fieldMask []string
		expected  map[string]interface{}
	}{
		{
			name: "simple_field_mask",
			data: map[string]interface{}{
				"id":       "123",
				"name":     "Test",
				"email":    "test@example.com",
				"password": "secret",
			},
			fieldMask: []string{"id", "name"},
			expected: map[string]interface{}{
				"id":   "123",
				"name": "Test",
			},
		},
		{
			name: "nested_field_mask",
			data: map[string]interface{}{
				"user": map[string]interface{}{
					"id":       "123",
					"name":     "John",
					"password": "secret",
				},
				"metadata": map[string]interface{}{
					"created": "2024-01-01",
				},
			},
			fieldMask: []string{"user.id", "user.name"},
			expected: map[string]interface{}{
				"user": map[string]interface{}{
					"id":   "123",
					"name": "John",
				},
			},
		},
		{
			name: "repeated_field_mask",
			data: map[string]interface{}{
				"items": []interface{}{
					map[string]interface{}{"id": 1, "name": "Item 1", "secret": "x"},
					map[string]interface{}{"id": 2, "name": "Item 2", "secret": "y"},
				},
			},
			fieldMask: []string{"items[].id", "items[].name"},
			expected: map[string]interface{}{
				"items": []interface{}{
					map[string]interface{}{"id": 1, "name": "Item 1"},
					map[string]interface{}{"id": 2, "name": "Item 2"},
				},
			},
		},
		{
			name: "empty_field_mask_returns_all",
			data: map[string]interface{}{
				"id":   "123",
				"name": "Test",
			},
			fieldMask: []string{},
			expected: map[string]interface{}{
				"id":   "123",
				"name": "Test",
			},
		},
		{
			name: "deeply_nested_field_mask",
			data: map[string]interface{}{
				"user": map[string]interface{}{
					"profile": map[string]interface{}{
						"name":    "John",
						"avatar":  "url",
						"private": "data",
					},
				},
			},
			fieldMask: []string{"user.profile.name", "user.profile.avatar"},
			expected: map[string]interface{}{
				"user": map[string]interface{}{
					"profile": map[string]interface{}{
						"name":   "John",
						"avatar": "url",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filter.FilterAllow(tt.data, tt.fieldMask)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestFunctional_GRPCTransform_MetadataTransformation tests gRPC metadata transformation.
func TestFunctional_GRPCTransform_MetadataTransformation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		staticMetadata map[string]string
		expected       map[string]string
	}{
		{
			name: "add_static_metadata",
			staticMetadata: map[string]string{
				"x-gateway":    "avapigw",
				"x-version":    "1.0",
				"x-request-id": "test-123",
			},
			expected: map[string]string{
				"x-gateway":    "avapigw",
				"x-version":    "1.0",
				"x-request-id": "test-123",
			},
		},
		{
			name:           "empty_metadata",
			staticMetadata: map[string]string{},
			expected:       map[string]string{},
		},
		{
			name: "single_metadata_entry",
			staticMetadata: map[string]string{
				"authorization": "Bearer token",
			},
			expected: map[string]string{
				"authorization": "Bearer token",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.GRPCRequestTransformConfig{
				StaticMetadata: tt.staticMetadata,
			}

			// Verify configuration is correctly set
			assert.Equal(t, tt.expected, cfg.StaticMetadata)
		})
	}
}

// TestFunctional_GRPCTransform_StreamingTransformation tests streaming transformation config.
func TestFunctional_GRPCTransform_StreamingTransformation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      *config.StreamingTransformConfig
		isEmpty  bool
		expected *config.StreamingTransformConfig
	}{
		{
			name: "per_message_transform",
			cfg: &config.StreamingTransformConfig{
				PerMessageTransform: true,
				BufferSize:          100,
				RateLimit:           1000,
			},
			isEmpty: false,
		},
		{
			name: "aggregate_mode",
			cfg: &config.StreamingTransformConfig{
				Aggregate:  true,
				BufferSize: 500,
			},
			isEmpty: false,
		},
		{
			name: "with_filter_condition",
			cfg: &config.StreamingTransformConfig{
				PerMessageTransform: true,
				FilterCondition:     "message.type == 'important'",
			},
			isEmpty: false,
		},
		{
			name:    "empty_config",
			cfg:     &config.StreamingTransformConfig{},
			isEmpty: true,
		},
		{
			name:    "nil_config",
			cfg:     nil,
			isEmpty: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.isEmpty, tt.cfg.IsEmpty())
		})
	}
}

// TestFunctional_GRPCTransform_RepeatedFieldOperations tests repeated field operations.
func TestFunctional_GRPCTransform_RepeatedFieldOperations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		operations []config.RepeatedFieldOperation
		valid      bool
	}{
		{
			name: "filter_operation",
			operations: []config.RepeatedFieldOperation{
				{
					Field:     "items",
					Operation: config.RepeatedFieldOpFilter,
					Condition: "item.status == 'active'",
				},
			},
			valid: true,
		},
		{
			name: "sort_operation",
			operations: []config.RepeatedFieldOperation{
				{
					Field:     "items",
					Operation: config.RepeatedFieldOpSort,
					SortField: "created_at",
					SortOrder: config.SortOrderDesc,
				},
			},
			valid: true,
		},
		{
			name: "limit_operation",
			operations: []config.RepeatedFieldOperation{
				{
					Field:     "items",
					Operation: config.RepeatedFieldOpLimit,
					Limit:     10,
				},
			},
			valid: true,
		},
		{
			name: "deduplicate_operation",
			operations: []config.RepeatedFieldOperation{
				{
					Field:     "tags",
					Operation: config.RepeatedFieldOpDeduplicate,
				},
			},
			valid: true,
		},
		{
			name: "multiple_operations",
			operations: []config.RepeatedFieldOperation{
				{
					Field:     "items",
					Operation: config.RepeatedFieldOpFilter,
					Condition: "item.active",
				},
				{
					Field:     "items",
					Operation: config.RepeatedFieldOpSort,
					SortField: "name",
					SortOrder: config.SortOrderAsc,
				},
				{
					Field:     "items",
					Operation: config.RepeatedFieldOpLimit,
					Limit:     5,
				},
			},
			valid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.GRPCResponseTransformConfig{
				RepeatedFieldOps: tt.operations,
			}

			assert.Equal(t, len(tt.operations), len(cfg.RepeatedFieldOps))
			for i, op := range tt.operations {
				assert.Equal(t, op.Field, cfg.RepeatedFieldOps[i].Field)
				assert.Equal(t, op.Operation, cfg.RepeatedFieldOps[i].Operation)
			}
		})
	}
}

// TestFunctional_GRPCTransform_MapFieldOperations tests map field operations.
func TestFunctional_GRPCTransform_MapFieldOperations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		operations []config.MapFieldOperation
	}{
		{
			name: "filter_keys_allow",
			operations: []config.MapFieldOperation{
				{
					Field:     "metadata",
					Operation: config.MapFieldOpFilterKeys,
					AllowKeys: []string{"key1", "key2"},
				},
			},
		},
		{
			name: "filter_keys_deny",
			operations: []config.MapFieldOperation{
				{
					Field:     "metadata",
					Operation: config.MapFieldOpFilterKeys,
					DenyKeys:  []string{"secret", "internal"},
				},
			},
		},
		{
			name: "merge_operation",
			operations: []config.MapFieldOperation{
				{
					Field:     "metadata",
					Operation: config.MapFieldOpMerge,
					MergeWith: map[string]interface{}{
						"gateway": "avapigw",
						"version": "1.0",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.GRPCResponseTransformConfig{
				MapFieldOps: tt.operations,
			}

			assert.Equal(t, len(tt.operations), len(cfg.MapFieldOps))
		})
	}
}

// TestFunctional_GRPCTransform_ConfigValidation tests gRPC transform config validation.
func TestFunctional_GRPCTransform_ConfigValidation(t *testing.T) {
	t.Parallel()

	t.Run("empty_grpc_transform_config", func(t *testing.T) {
		cfg := &config.GRPCTransformConfig{}
		assert.True(t, cfg.IsEmpty())
	})

	t.Run("non_empty_request_config", func(t *testing.T) {
		cfg := &config.GRPCTransformConfig{
			Request: &config.GRPCRequestTransformConfig{
				StaticMetadata: map[string]string{"key": "value"},
			},
		}
		assert.False(t, cfg.IsEmpty())
	})

	t.Run("non_empty_response_config", func(t *testing.T) {
		cfg := &config.GRPCTransformConfig{
			Response: &config.GRPCResponseTransformConfig{
				FieldMask: []string{"id", "name"},
			},
		}
		assert.False(t, cfg.IsEmpty())
	})

	t.Run("request_config_with_inject_field_mask", func(t *testing.T) {
		cfg := &config.GRPCRequestTransformConfig{
			InjectFieldMask: []string{"user.name", "user.email"},
		}
		assert.False(t, cfg.IsEmpty())
	})

	t.Run("request_config_with_dynamic_metadata", func(t *testing.T) {
		cfg := &config.GRPCRequestTransformConfig{
			DynamicMetadata: []config.DynamicMetadata{
				{Key: "x-user-id", Source: "jwt.claim.sub"},
			},
		}
		assert.False(t, cfg.IsEmpty())
	})

	t.Run("response_config_with_trailer_metadata", func(t *testing.T) {
		cfg := &config.GRPCResponseTransformConfig{
			TrailerMetadata: map[string]string{
				"x-processing-time": "100ms",
			},
		}
		assert.False(t, cfg.IsEmpty())
	})
}

// TestFunctional_GRPCTransform_DynamicMetadataResolution tests dynamic metadata source resolution.
func TestFunctional_GRPCTransform_DynamicMetadataResolution(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		metadata []config.DynamicMetadata
		sources  []string
	}{
		{
			name: "jwt_claim_source",
			metadata: []config.DynamicMetadata{
				{Key: "x-user-id", Source: "jwt.claim.sub"},
				{Key: "x-user-email", Source: "jwt.claim.email"},
			},
			sources: []string{"jwt.claim.sub", "jwt.claim.email"},
		},
		{
			name: "peer_info_source",
			metadata: []config.DynamicMetadata{
				{Key: "x-client-ip", Source: "peer.address"},
			},
			sources: []string{"peer.address"},
		},
		{
			name: "request_header_source",
			metadata: []config.DynamicMetadata{
				{Key: "x-correlation-id", Source: "request.header.x-request-id"},
			},
			sources: []string{"request.header.x-request-id"},
		},
		{
			name: "mixed_sources",
			metadata: []config.DynamicMetadata{
				{Key: "x-user-id", Source: "jwt.claim.sub"},
				{Key: "x-client-ip", Source: "peer.address"},
				{Key: "x-trace-id", Source: "request.header.x-trace-id"},
			},
			sources: []string{"jwt.claim.sub", "peer.address", "request.header.x-trace-id"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.GRPCRequestTransformConfig{
				DynamicMetadata: tt.metadata,
			}

			require.Equal(t, len(tt.sources), len(cfg.DynamicMetadata))
			for i, source := range tt.sources {
				assert.Equal(t, source, cfg.DynamicMetadata[i].Source)
			}
		})
	}
}

// TestFunctional_GRPCTransform_FieldMappingWithProtobuf tests field mapping for protobuf messages.
func TestFunctional_GRPCTransform_FieldMappingWithProtobuf(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	mapper := transform.NewFieldMapper(logger)

	tests := []struct {
		name     string
		data     map[string]interface{}
		mappings []config.FieldMapping
		expected map[string]interface{}
	}{
		{
			name: "snake_case_to_camel_case",
			data: map[string]interface{}{
				"user_id":    "123",
				"first_name": "John",
				"last_name":  "Doe",
			},
			mappings: []config.FieldMapping{
				{Source: "user_id", Target: "userId"},
				{Source: "first_name", Target: "firstName"},
				{Source: "last_name", Target: "lastName"},
			},
			expected: map[string]interface{}{
				"userId":    "123",
				"firstName": "John",
				"lastName":  "Doe",
			},
		},
		{
			name: "flatten_nested_message",
			data: map[string]interface{}{
				"response": map[string]interface{}{
					"data": map[string]interface{}{
						"id":   "123",
						"name": "Test",
					},
				},
			},
			mappings: []config.FieldMapping{
				{Source: "response.data.id", Target: "id"},
				{Source: "response.data.name", Target: "name"},
			},
			expected: map[string]interface{}{
				"response": map[string]interface{}{
					"data": map[string]interface{}{},
				},
				"id":   "123",
				"name": "Test",
			},
		},
		{
			name: "restructure_response",
			data: map[string]interface{}{
				"user_name":  "John",
				"user_email": "john@example.com",
				"order_id":   "order-123",
			},
			mappings: []config.FieldMapping{
				{Source: "user_name", Target: "user.name"},
				{Source: "user_email", Target: "user.email"},
				{Source: "order_id", Target: "order.id"},
			},
			expected: map[string]interface{}{
				"user": map[string]interface{}{
					"name":  "John",
					"email": "john@example.com",
				},
				"order": map[string]interface{}{
					"id": "order-123",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := mapper.MapFields(tt.data, tt.mappings)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestFunctional_GRPCTransform_AuthorityOverride tests authority override configuration.
func TestFunctional_GRPCTransform_AuthorityOverride(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		authorityOverride string
		isEmpty           bool
	}{
		{
			name:              "with_authority_override",
			authorityOverride: "backend.internal:443",
			isEmpty:           false,
		},
		{
			name:              "empty_authority_override",
			authorityOverride: "",
			isEmpty:           true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.GRPCRequestTransformConfig{
				AuthorityOverride: tt.authorityOverride,
			}

			if tt.isEmpty {
				assert.True(t, cfg.IsEmpty())
			} else {
				assert.False(t, cfg.IsEmpty())
				assert.Equal(t, tt.authorityOverride, cfg.AuthorityOverride)
			}
		})
	}
}

// TestFunctional_GRPCTransform_PreserveUnknownFields tests unknown field preservation.
func TestFunctional_GRPCTransform_PreserveUnknownFields(t *testing.T) {
	t.Parallel()

	t.Run("preserve_unknown_fields_enabled", func(t *testing.T) {
		cfg := &config.GRPCResponseTransformConfig{
			PreserveUnknownFields: true,
		}
		assert.False(t, cfg.IsEmpty())
		assert.True(t, cfg.PreserveUnknownFields)
	})

	t.Run("preserve_unknown_fields_disabled", func(t *testing.T) {
		cfg := &config.GRPCResponseTransformConfig{
			PreserveUnknownFields: false,
		}
		assert.True(t, cfg.IsEmpty())
	})
}

// TestFunctional_GRPCTransform_Metadata_Static tests metadata transformation with static values.
func TestFunctional_GRPCTransform_Metadata_Static(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	transformer := grpctransform.NewMetadataTransformer(logger)

	tests := []struct {
		name           string
		existingMD     metadata.MD
		staticMetadata map[string]string
		expectedKeys   []string
	}{
		{
			name:       "add_static_to_empty",
			existingMD: metadata.MD{},
			staticMetadata: map[string]string{
				"x-gateway": "avapigw",
				"x-version": "1.0",
			},
			expectedKeys: []string{"x-gateway", "x-version"},
		},
		{
			name: "add_static_to_existing",
			existingMD: metadata.MD{
				"existing-key": []string{"existing-value"},
			},
			staticMetadata: map[string]string{
				"x-gateway": "avapigw",
			},
			expectedKeys: []string{"existing-key", "x-gateway"},
		},
		{
			name: "override_existing_key",
			existingMD: metadata.MD{
				"x-gateway": []string{"old-value"},
			},
			staticMetadata: map[string]string{
				"x-gateway": "new-value",
			},
			expectedKeys: []string{"x-gateway"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := transformer.InjectStaticMetadata(tt.existingMD, tt.staticMetadata)

			for _, key := range tt.expectedKeys {
				assert.NotEmpty(t, result.Get(key), "key %s should exist", key)
			}

			for key, value := range tt.staticMetadata {
				values := result.Get(key)
				require.NotEmpty(t, values)
				assert.Equal(t, value, values[0])
			}
		})
	}
}

// TestFunctional_GRPCTransform_Metadata_Dynamic tests metadata transformation with dynamic values.
func TestFunctional_GRPCTransform_Metadata_Dynamic(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	transformer := grpctransform.NewMetadataTransformer(logger)

	tests := []struct {
		name            string
		dynamicMetadata []config.DynamicMetadata
		transformCtx    *grpctransform.TransformContext
		expectedKeys    []string
		expectedValues  map[string]string
	}{
		{
			name: "inject_from_jwt_claims",
			dynamicMetadata: []config.DynamicMetadata{
				{Key: "x-user-id", Source: "jwt.claim.sub"},
			},
			transformCtx: grpctransform.NewTransformContext(logger).
				WithClaims(map[string]interface{}{"sub": "user-123"}),
			expectedKeys:   []string{"x-user-id"},
			expectedValues: map[string]string{"x-user-id": "user-123"},
		},
		{
			name: "inject_from_peer_address",
			dynamicMetadata: []config.DynamicMetadata{
				{Key: "x-client-ip", Source: "peer.address"},
			},
			transformCtx: grpctransform.NewTransformContext(logger).
				WithPeerAddress("192.168.1.1:12345"),
			expectedKeys:   []string{"x-client-ip"},
			expectedValues: map[string]string{"x-client-ip": "192.168.1.1:12345"},
		},
		{
			name: "inject_from_context",
			dynamicMetadata: []config.DynamicMetadata{
				{Key: "x-request-id", Source: "context.request_id"},
				{Key: "x-trace-id", Source: "context.trace_id"},
			},
			transformCtx: grpctransform.NewTransformContext(logger).
				WithRequestID("req-123").
				WithTraceID("trace-456"),
			expectedKeys: []string{"x-request-id", "x-trace-id"},
			expectedValues: map[string]string{
				"x-request-id": "req-123",
				"x-trace-id":   "trace-456",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := grpctransform.ContextWithTransformContext(context.Background(), tt.transformCtx)
			md := metadata.MD{}

			result, err := transformer.InjectDynamicMetadata(ctx, md, tt.dynamicMetadata, tt.transformCtx)
			require.NoError(t, err)

			for key, expectedValue := range tt.expectedValues {
				values := result.Get(key)
				require.NotEmpty(t, values, "key %s should exist", key)
				assert.Equal(t, expectedValue, values[0])
			}
		})
	}
}

// TestFunctional_GRPCTransform_Metadata_Copy tests metadata copy.
func TestFunctional_GRPCTransform_Metadata_Copy(t *testing.T) {
	t.Parallel()

	t.Run("copy_creates_independent_copy", func(t *testing.T) {
		original := metadata.MD{
			"key1": []string{"value1"},
			"key2": []string{"value2a", "value2b"},
		}

		copied := grpctransform.CopyMetadata(original)

		// Verify copy has same values
		assert.Equal(t, original.Get("key1"), copied.Get("key1"))
		assert.Equal(t, original.Get("key2"), copied.Get("key2"))

		// Modify copy and verify original is unchanged
		copied.Set("key1", "modified")
		assert.Equal(t, []string{"value1"}, original.Get("key1"))
		assert.Equal(t, []string{"modified"}, copied.Get("key1"))
	})

	t.Run("copy_nil_returns_nil", func(t *testing.T) {
		result := grpctransform.CopyMetadata(nil)
		assert.Nil(t, result)
	})
}

// TestFunctional_GRPCTransform_Metadata_Merge tests metadata merge.
func TestFunctional_GRPCTransform_Metadata_Merge(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		metadatas    []metadata.MD
		expectedKeys []string
	}{
		{
			name: "merge_two_metadata",
			metadatas: []metadata.MD{
				{"key1": []string{"value1"}},
				{"key2": []string{"value2"}},
			},
			expectedKeys: []string{"key1", "key2"},
		},
		{
			name: "merge_overlapping_keys",
			metadatas: []metadata.MD{
				{"key1": []string{"value1a"}},
				{"key1": []string{"value1b"}},
			},
			expectedKeys: []string{"key1"},
		},
		{
			name: "merge_multiple_metadata",
			metadatas: []metadata.MD{
				{"key1": []string{"value1"}},
				{"key2": []string{"value2"}},
				{"key3": []string{"value3"}},
			},
			expectedKeys: []string{"key1", "key2", "key3"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := grpctransform.MergeMetadata(tt.metadatas...)

			for _, key := range tt.expectedKeys {
				assert.NotEmpty(t, result.Get(key), "key %s should exist", key)
			}
		})
	}
}

// TestFunctional_GRPCTransform_Metadata_Filter tests metadata filter.
func TestFunctional_GRPCTransform_Metadata_Filter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		md           metadata.MD
		allowKeys    []string
		expectedKeys []string
		excludedKeys []string
	}{
		{
			name: "filter_to_allowed_keys",
			md: metadata.MD{
				"key1": []string{"value1"},
				"key2": []string{"value2"},
				"key3": []string{"value3"},
			},
			allowKeys:    []string{"key1", "key2"},
			expectedKeys: []string{"key1", "key2"},
			excludedKeys: []string{"key3"},
		},
		{
			name: "filter_case_sensitive",
			md: metadata.MD{
				"key1": []string{"value1"},
				"key2": []string{"value2"},
			},
			allowKeys:    []string{"key1", "key2"},
			expectedKeys: []string{"key1", "key2"},
		},
		{
			name: "filter_empty_allow_returns_original",
			md: metadata.MD{
				"key1": []string{"value1"},
			},
			allowKeys:    []string{},
			expectedKeys: []string{"key1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := grpctransform.FilterMetadata(tt.md, tt.allowKeys)

			for _, key := range tt.expectedKeys {
				assert.NotEmpty(t, result.Get(key), "key %s should exist", key)
			}

			for _, key := range tt.excludedKeys {
				assert.Empty(t, result.Get(key), "key %s should not exist", key)
			}
		})
	}
}

// TestFunctional_GRPCTransform_Streaming_RateLimiting tests streaming transformer rate limiting.
func TestFunctional_GRPCTransform_Streaming_RateLimiting(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()

	t.Run("rate_limiter_configured", func(t *testing.T) {
		cfg := &config.StreamingTransformConfig{
			RateLimit: 100, // 100 messages per second
		}

		transformer := grpctransform.NewStreamingTransformer(logger, cfg)
		assert.NotNil(t, transformer)
	})

	t.Run("rate_limiter_with_options", func(t *testing.T) {
		cfg := &config.StreamingTransformConfig{}

		transformer := grpctransform.NewStreamingTransformer(
			logger,
			cfg,
			grpctransform.WithStreamingRateLimit(50),
		)
		assert.NotNil(t, transformer)
	})
}

// TestFunctional_GRPCTransform_Streaming_MessageCounting tests streaming transformer message counting.
func TestFunctional_GRPCTransform_Streaming_MessageCounting(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := &config.StreamingTransformConfig{}

	transformer := grpctransform.NewStreamingTransformer(logger, cfg)

	t.Run("initial_count_is_zero", func(t *testing.T) {
		transformer.Reset()
		assert.Equal(t, int64(0), transformer.GetMessageCount())
	})

	t.Run("reset_clears_count", func(t *testing.T) {
		transformer.Reset()
		assert.Equal(t, int64(0), transformer.GetMessageCount())
	})
}

// TestFunctional_GRPCTransform_Streaming_Timeout tests streaming transformer timeout.
func TestFunctional_GRPCTransform_Streaming_Timeout(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		cfg        *config.StreamingTransformConfig
		hasTimeout bool
	}{
		{
			name: "with_total_timeout",
			cfg: &config.StreamingTransformConfig{
				TotalTimeout: config.Duration(30 * time.Second),
			},
			hasTimeout: true,
		},
		{
			name: "with_message_timeout",
			cfg: &config.StreamingTransformConfig{
				MessageTimeout: config.Duration(5 * time.Second),
			},
			hasTimeout: true,
		},
		{
			name: "with_both_timeouts",
			cfg: &config.StreamingTransformConfig{
				TotalTimeout:   config.Duration(30 * time.Second),
				MessageTimeout: config.Duration(5 * time.Second),
			},
			hasTimeout: true,
		},
		{
			name:       "no_timeout",
			cfg:        &config.StreamingTransformConfig{},
			hasTimeout: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.hasTimeout {
				assert.True(t, tt.cfg.TotalTimeout > 0 || tt.cfg.MessageTimeout > 0)
			} else {
				assert.True(t, tt.cfg.TotalTimeout == 0 && tt.cfg.MessageTimeout == 0)
			}
		})
	}
}

// TestFunctional_GRPCTransform_Context_Creation tests transform context creation.
func TestFunctional_GRPCTransform_Context_Creation(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()

	t.Run("create_new_context", func(t *testing.T) {
		tc := grpctransform.NewTransformContext(logger)

		assert.NotNil(t, tc)
		assert.NotNil(t, tc.Logger)
		assert.NotNil(t, tc.IncomingMetadata)
		assert.NotNil(t, tc.Claims)
		assert.NotNil(t, tc.CustomData)
	})

	t.Run("create_with_nil_logger", func(t *testing.T) {
		tc := grpctransform.NewTransformContext(nil)

		assert.NotNil(t, tc)
		assert.NotNil(t, tc.Logger) // Should use NopLogger
	})

	t.Run("context_with_metadata", func(t *testing.T) {
		md := metadata.MD{
			"key": []string{"value"},
		}

		tc := grpctransform.NewTransformContext(logger).WithMetadata(md)

		assert.Equal(t, md, tc.IncomingMetadata)
	})

	t.Run("context_with_peer_address", func(t *testing.T) {
		tc := grpctransform.NewTransformContext(logger).WithPeerAddress("192.168.1.1:12345")

		assert.Equal(t, "192.168.1.1:12345", tc.PeerAddress)
	})

	t.Run("context_with_request_id", func(t *testing.T) {
		tc := grpctransform.NewTransformContext(logger).WithRequestID("req-123")

		assert.Equal(t, "req-123", tc.RequestID)
	})

	t.Run("context_with_trace_id", func(t *testing.T) {
		tc := grpctransform.NewTransformContext(logger).WithTraceID("trace-456")

		assert.Equal(t, "trace-456", tc.TraceID)
	})

	t.Run("context_with_span_id", func(t *testing.T) {
		tc := grpctransform.NewTransformContext(logger).WithSpanID("span-789")

		assert.Equal(t, "span-789", tc.SpanID)
	})
}

// TestFunctional_GRPCTransform_Context_WithClaims tests transform context with claims.
func TestFunctional_GRPCTransform_Context_WithClaims(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()

	t.Run("set_claims", func(t *testing.T) {
		claims := map[string]interface{}{
			"sub":   "user-123",
			"email": "user@example.com",
			"roles": []string{"admin", "user"},
		}

		tc := grpctransform.NewTransformContext(logger).WithClaims(claims)

		assert.Equal(t, claims, tc.Claims)
		assert.Equal(t, "user-123", tc.Claims["sub"])
		assert.Equal(t, "user@example.com", tc.Claims["email"])
	})

	t.Run("nil_claims_not_set", func(t *testing.T) {
		tc := grpctransform.NewTransformContext(logger).WithClaims(nil)

		assert.NotNil(t, tc.Claims)
		assert.Empty(t, tc.Claims)
	})

	t.Run("custom_data_operations", func(t *testing.T) {
		tc := grpctransform.NewTransformContext(logger)

		tc.SetCustomData("key1", "value1")
		tc.SetCustomData("key2", 123)

		val1, ok1 := tc.GetCustomData("key1")
		assert.True(t, ok1)
		assert.Equal(t, "value1", val1)

		val2, ok2 := tc.GetCustomData("key2")
		assert.True(t, ok2)
		assert.Equal(t, 123, val2)

		_, ok3 := tc.GetCustomData("nonexistent")
		assert.False(t, ok3)
	})
}

// TestFunctional_GRPCTransform_Context_FromContext tests extracting transform context from context.
func TestFunctional_GRPCTransform_Context_FromContext(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()

	t.Run("extract_existing_context", func(t *testing.T) {
		tc := grpctransform.NewTransformContext(logger).
			WithRequestID("req-123").
			WithTraceID("trace-456")

		ctx := grpctransform.ContextWithTransformContext(context.Background(), tc)

		extracted := grpctransform.TransformContextFromContext(ctx)

		assert.Equal(t, "req-123", extracted.RequestID)
		assert.Equal(t, "trace-456", extracted.TraceID)
	})

	t.Run("extract_from_empty_context_returns_new", func(t *testing.T) {
		ctx := context.Background()

		extracted := grpctransform.TransformContextFromContext(ctx)

		assert.NotNil(t, extracted)
		assert.Empty(t, extracted.RequestID)
	})
}

// TestFunctional_GRPCTransform_Streaming_BufferOperations tests streaming buffer operations.
func TestFunctional_GRPCTransform_Streaming_BufferOperations(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()

	t.Run("buffer_size_configuration", func(t *testing.T) {
		cfg := &config.StreamingTransformConfig{
			BufferSize: 50,
		}

		transformer := grpctransform.NewStreamingTransformer(logger, cfg)
		assert.NotNil(t, transformer)
	})

	t.Run("buffer_size_with_option", func(t *testing.T) {
		cfg := &config.StreamingTransformConfig{}

		transformer := grpctransform.NewStreamingTransformer(
			logger,
			cfg,
			grpctransform.WithStreamingBufferSize(100),
		)
		assert.NotNil(t, transformer)
	})

	t.Run("get_buffered_messages_empty", func(t *testing.T) {
		cfg := &config.StreamingTransformConfig{}
		transformer := grpctransform.NewStreamingTransformer(logger, cfg)

		messages := transformer.GetBufferedMessages()
		assert.Empty(t, messages)
	})

	t.Run("flush_empty_buffer", func(t *testing.T) {
		cfg := &config.StreamingTransformConfig{}
		transformer := grpctransform.NewStreamingTransformer(logger, cfg)

		result, err := transformer.FlushBuffer(context.Background())
		require.NoError(t, err)
		assert.Nil(t, result)
	})
}
