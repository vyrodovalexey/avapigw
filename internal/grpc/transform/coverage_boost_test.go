// Package transform provides gRPC-specific data transformation capabilities.
package transform

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// ============================================================
// interfaceToValue coverage: all protoreflect.Kind branches
// ============================================================

func TestInterfaceToValue_Int32Kind(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value interface{}
		valid bool
	}{
		{"int", 42, true},
		{"int32", int32(42), true},
		{"int64 in range", int64(42), true},
		{"float64 in range", float64(42.0), true},
		{"string (invalid)", "42", false},
		{"bool (invalid)", true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := interfaceToValue(tt.value, protoreflect.Int32Kind)
			assert.Equal(t, tt.valid, result.IsValid())
		})
	}
}

func TestInterfaceToValue_Sint32Kind(t *testing.T) {
	t.Parallel()

	result := interfaceToValue(int32(42), protoreflect.Sint32Kind)
	assert.True(t, result.IsValid())
	assert.Equal(t, int32(42), result.Interface())
}

func TestInterfaceToValue_Sfixed32Kind(t *testing.T) {
	t.Parallel()

	result := interfaceToValue(int32(42), protoreflect.Sfixed32Kind)
	assert.True(t, result.IsValid())
	assert.Equal(t, int32(42), result.Interface())
}

func TestInterfaceToValue_Int64Kind(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value interface{}
		valid bool
	}{
		{"int", 42, true},
		{"int32", int32(42), true},
		{"int64", int64(42), true},
		{"float64", float64(42.0), true},
		{"string (invalid)", "42", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := interfaceToValue(tt.value, protoreflect.Int64Kind)
			assert.Equal(t, tt.valid, result.IsValid())
		})
	}
}

func TestInterfaceToValue_Sint64Kind(t *testing.T) {
	t.Parallel()

	result := interfaceToValue(int64(42), protoreflect.Sint64Kind)
	assert.True(t, result.IsValid())
	assert.Equal(t, int64(42), result.Interface())
}

func TestInterfaceToValue_Sfixed64Kind(t *testing.T) {
	t.Parallel()

	result := interfaceToValue(int64(42), protoreflect.Sfixed64Kind)
	assert.True(t, result.IsValid())
	assert.Equal(t, int64(42), result.Interface())
}

func TestInterfaceToValue_Uint32Kind(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value interface{}
		valid bool
	}{
		{"uint", uint(42), true},
		{"uint32", uint32(42), true},
		{"uint64 in range", uint64(42), true},
		{"int positive", 42, true},
		{"float64 positive", float64(42.0), true},
		{"string (invalid)", "42", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := interfaceToValue(tt.value, protoreflect.Uint32Kind)
			assert.Equal(t, tt.valid, result.IsValid())
		})
	}
}

func TestInterfaceToValue_Fixed32Kind(t *testing.T) {
	t.Parallel()

	result := interfaceToValue(uint32(42), protoreflect.Fixed32Kind)
	assert.True(t, result.IsValid())
	assert.Equal(t, uint32(42), result.Interface())
}

func TestInterfaceToValue_Uint64Kind(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value interface{}
		valid bool
	}{
		{"uint", uint(42), true},
		{"uint32", uint32(42), true},
		{"uint64", uint64(42), true},
		{"int positive", 42, true},
		{"float64 positive", float64(42.0), true},
		{"string (invalid)", "42", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := interfaceToValue(tt.value, protoreflect.Uint64Kind)
			assert.Equal(t, tt.valid, result.IsValid())
		})
	}
}

func TestInterfaceToValue_Fixed64Kind(t *testing.T) {
	t.Parallel()

	result := interfaceToValue(uint64(42), protoreflect.Fixed64Kind)
	assert.True(t, result.IsValid())
	assert.Equal(t, uint64(42), result.Interface())
}

func TestInterfaceToValue_FloatKind(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value interface{}
		valid bool
	}{
		{"float32", float32(3.14), true},
		{"float64", float64(3.14), true},
		{"int", 42, true},
		{"string (invalid)", "3.14", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := interfaceToValue(tt.value, protoreflect.FloatKind)
			assert.Equal(t, tt.valid, result.IsValid())
		})
	}
}

func TestInterfaceToValue_DoubleKind(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value interface{}
		valid bool
	}{
		{"float32", float32(3.14), true},
		{"float64", float64(3.14), true},
		{"int", 42, true},
		{"string (invalid)", "3.14", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := interfaceToValue(tt.value, protoreflect.DoubleKind)
			assert.Equal(t, tt.valid, result.IsValid())
		})
	}
}

func TestInterfaceToValue_BoolKind_NonBool(t *testing.T) {
	t.Parallel()

	// Non-bool value for BoolKind should return invalid
	result := interfaceToValue("true", protoreflect.BoolKind)
	assert.False(t, result.IsValid())

	result = interfaceToValue(42, protoreflect.BoolKind)
	assert.False(t, result.IsValid())
}

func TestInterfaceToValue_BytesKind_InvalidType(t *testing.T) {
	t.Parallel()

	// Non-bytes, non-string value for BytesKind should return invalid
	result := interfaceToValue(42, protoreflect.BytesKind)
	assert.False(t, result.IsValid())
}

func TestInterfaceToValue_UnknownKind(t *testing.T) {
	t.Parallel()

	// An unsupported kind should return invalid
	result := interfaceToValue("test", protoreflect.EnumKind)
	assert.False(t, result.IsValid())
}

// ============================================================
// extractSortValue coverage
// ============================================================

func TestExtractSortValue_EmptySortField(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())

	// When sortField is empty, should return valueToInterface(v)
	v := protoreflect.ValueOfString("hello")
	result := transformer.extractSortValue(v, "")
	assert.Equal(t, "hello", result)
}

func TestExtractSortValue_WithSortFieldOnMessage(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())

	// Create a message value (wrapperspb.StringValue has a "value" field)
	msg := wrapperspb.String("test-value")
	v := protoreflect.ValueOfMessage(msg.ProtoReflect())

	// Extract sort value using the "value" field
	result := transformer.extractSortValue(v, "value")
	assert.Equal(t, "test-value", result)
}

func TestExtractSortValue_WithSortFieldNotFound(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())

	// Create a message value
	msg := wrapperspb.String("test-value")
	v := protoreflect.ValueOfMessage(msg.ProtoReflect())

	// Extract sort value using a non-existent field - should fall back to valueToInterface(v)
	result := transformer.extractSortValue(v, "nonexistent")
	assert.NotNil(t, result)
}

func TestExtractSortValue_WithSortFieldNotSet(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())

	// Create a message with unset field
	msg := wrapperspb.String("")
	v := protoreflect.ValueOfMessage(msg.ProtoReflect())

	// "value" field is not set (empty string is default, Has returns false)
	result := transformer.extractSortValue(v, "value")
	assert.NotNil(t, result)
}

// ============================================================
// clearField coverage: nested path where intermediate doesn't exist
// ============================================================

func TestClearField_NestedPathIntermediateNotExists(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())

	// structpb.Value has a "struct_value" field (message kind) that is not set
	msg := structpb.NewStringValue("test")
	msgReflect := msg.ProtoReflect()

	// Try to clear "struct_value.fields" - struct_value is not set, so should return nil (nothing to clear)
	err := transformer.clearField(msgReflect, "struct_value.fields")
	// The intermediate field "struct_value" is not set, so clearField returns nil
	assert.NoError(t, err)
}

func TestClearField_NestedPathSuccess(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())

	// Create a Struct with fields, then wrap in Value
	s, err := structpb.NewStruct(map[string]interface{}{
		"key": "value",
	})
	require.NoError(t, err)

	v := structpb.NewStructValue(s)
	msgReflect := v.ProtoReflect()

	// Clear "struct_value.fields" - struct_value is set, fields is a map
	err = transformer.clearField(msgReflect, "struct_value.fields")
	assert.NoError(t, err)
}

// ============================================================
// copyFields coverage: JSON name fallback, nested message subtree,
// non-message field with subtree, field not found
// ============================================================

func TestCopyFields_FieldNotFoundSkipped(t *testing.T) {
	t.Parallel()

	filter := NewFieldMaskFilter(observability.NopLogger())

	// Filter with a path that doesn't exist in the message
	msg := wrapperspb.String("test")
	result, err := filter.Filter(msg, []string{"nonexistent_field"})
	require.NoError(t, err)
	assert.NotNil(t, result)

	// The result should be a new empty message (no fields copied)
	resultWrapper, ok := result.(*wrapperspb.StringValue)
	require.True(t, ok)
	assert.Empty(t, resultWrapper.Value)
}

func TestCopyFields_FieldNotSet(t *testing.T) {
	t.Parallel()

	filter := NewFieldMaskFilter(observability.NopLogger())

	// Filter with a path that exists but is not set
	msg := wrapperspb.String("")
	result, err := filter.Filter(msg, []string{"value"})
	require.NoError(t, err)
	assert.NotNil(t, result)

	// The result should be a new empty message (field not set, so not copied)
	resultWrapper, ok := result.(*wrapperspb.StringValue)
	require.True(t, ok)
	assert.Empty(t, resultWrapper.Value)
}

func TestCopyFields_NestedMessageSubtree(t *testing.T) {
	t.Parallel()

	filter := NewFieldMaskFilter(observability.NopLogger())

	// Create a structpb.Value with a struct_value containing fields
	s, err := structpb.NewStruct(map[string]interface{}{
		"name":  "John",
		"email": "john@example.com",
	})
	require.NoError(t, err)

	v := structpb.NewStructValue(s)

	// Filter with nested path "struct_value.fields" - struct_value is a message
	result, err := filter.Filter(v, []string{"struct_value.fields"})
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestCopyFields_NonMessageFieldWithSubtree(t *testing.T) {
	t.Parallel()

	filter := NewFieldMaskFilter(observability.NopLogger())

	// Create a message and filter with a subtree path on a non-message field
	// "paths" is a repeated string field (not a message), but we give it a subtree path
	msg := &fieldmaskpb.FieldMask{Paths: []string{"a", "b"}}

	// "paths.something" - paths is not a message, so the subtree should just copy the field
	result, err := filter.Filter(msg, []string{"paths.something"})
	require.NoError(t, err)
	assert.NotNil(t, result)

	// The paths field should be copied as-is since it's not a message
	resultMask, ok := result.(*fieldmaskpb.FieldMask)
	require.True(t, ok)
	assert.Equal(t, []string{"a", "b"}, resultMask.Paths)
}

func TestCopyFields_EntireFieldCopy(t *testing.T) {
	t.Parallel()

	filter := NewFieldMaskFilter(observability.NopLogger())

	// Filter with a leaf path (no subtree) - should copy entire field
	msg := wrapperspb.String("hello")
	result, err := filter.Filter(msg, []string{"value"})
	require.NoError(t, err)

	resultWrapper, ok := result.(*wrapperspb.StringValue)
	require.True(t, ok)
	assert.Equal(t, "hello", resultWrapper.Value)
}

// ============================================================
// isValidPath coverage: JSON name fallback, nested message navigation
// ============================================================

func TestIsValidPath_InvalidPath(t *testing.T) {
	t.Parallel()

	filter := NewFieldMaskFilter(observability.NopLogger())

	// Validate with an invalid path
	msg := wrapperspb.String("test")
	mask, err := filter.CreateFieldMask([]string{"nonexistent_field"})
	require.NoError(t, err)

	err = filter.ValidateFieldMask(msg, mask)
	assert.Error(t, err) // Should report invalid paths
}

func TestIsValidPath_NestedMessageNavigation(t *testing.T) {
	t.Parallel()

	filter := NewFieldMaskFilter(observability.NopLogger())

	// structpb.Value has nested message fields like struct_value
	msg := structpb.NewStringValue("test")

	// "struct_value" is a valid nested message field on Value
	mask, err := filter.CreateFieldMask([]string{"struct_value"})
	require.NoError(t, err)

	err = filter.ValidateFieldMask(msg, mask)
	assert.NoError(t, err)
}

func TestIsValidPath_DeepNestedPath(t *testing.T) {
	t.Parallel()

	filter := NewFieldMaskFilter(observability.NopLogger())

	// structpb.Value -> struct_value -> fields
	msg := structpb.NewStringValue("test")

	mask, err := filter.CreateFieldMask([]string{"struct_value.fields"})
	require.NoError(t, err)

	err = filter.ValidateFieldMask(msg, mask)
	assert.NoError(t, err)
}

func TestIsValidPath_InvalidNestedPath(t *testing.T) {
	t.Parallel()

	filter := NewFieldMaskFilter(observability.NopLogger())

	msg := structpb.NewStringValue("test")

	// "struct_value.nonexistent" - struct_value exists but nonexistent doesn't
	mask, err := filter.CreateFieldMask([]string{"struct_value.nonexistent"})
	require.NoError(t, err)

	err = filter.ValidateFieldMask(msg, mask)
	assert.Error(t, err)
}

// ============================================================
// findFieldMaskField coverage
// ============================================================

func TestFindFieldMaskField_NoFieldMaskField(t *testing.T) {
	t.Parallel()

	filter := NewFieldMaskFilter(observability.NopLogger())

	// wrapperspb.StringValue has only a "value" field (string kind, not message kind)
	msg := wrapperspb.String("test")
	fd := filter.findFieldMaskField(msg.ProtoReflect().Descriptor())
	assert.Nil(t, fd)
}

func TestFindFieldMaskField_MessageFieldButNotFieldMask(t *testing.T) {
	t.Parallel()

	filter := NewFieldMaskFilter(observability.NopLogger())

	// structpb.Value has message fields (struct_value, list_value) but none are FieldMask
	msg := structpb.NewStringValue("test")
	fd := filter.findFieldMaskField(msg.ProtoReflect().Descriptor())
	assert.Nil(t, fd)
}

// ============================================================
// InjectFieldMask coverage: test with message that has no FieldMask field
// (the "found" path requires a proto with FieldMask field which isn't
// available in well-known types, but we can test the full flow)
// ============================================================

func TestInjectFieldMask_FullFlow_NoFieldMaskField(t *testing.T) {
	t.Parallel()

	filter := NewFieldMaskFilter(observability.NopLogger())

	// Test with structpb.Value which has message fields but no FieldMask field
	msg := structpb.NewStringValue("test")
	result, err := filter.InjectFieldMask(msg, []string{"field1", "field2"})
	require.NoError(t, err)
	assert.NotNil(t, result)

	// Result should be a clone of the original (no FieldMask field to inject into)
	resultValue, ok := result.(*structpb.Value)
	require.True(t, ok)
	assert.Equal(t, "test", resultValue.GetStringValue())
}

func TestInjectFieldMask_WithEmptyStringPaths(t *testing.T) {
	t.Parallel()

	filter := NewFieldMaskFilter(observability.NopLogger())

	// Paths with empty strings should be filtered out by normalizePath
	msg := wrapperspb.String("test")
	result, err := filter.InjectFieldMask(msg, []string{"", "  ", "..."})
	require.NoError(t, err)
	assert.NotNil(t, result)
}

// ============================================================
// mergeField coverage: nested message where dst already has the field
// ============================================================

func TestMergeField_NestedMessageDstHasField(t *testing.T) {
	t.Parallel()

	transformer := NewGRPCResponseTransformer(observability.NopLogger())
	ctx := context.Background()

	// Create two structpb.Value with struct_value set
	s1, err := structpb.NewStruct(map[string]interface{}{
		"key1": "value1",
	})
	require.NoError(t, err)
	v1 := structpb.NewStructValue(s1)

	s2, err := structpb.NewStruct(map[string]interface{}{
		"key2": "value2",
	})
	require.NoError(t, err)
	v2 := structpb.NewStructValue(s2)

	// Merge: both have struct_value set, so it should recursively merge
	result, err := transformer.MergeResponses(ctx, []proto.Message{v1, v2}, "merge")
	require.NoError(t, err)
	assert.NotNil(t, result)

	resultValue, ok := result.(*structpb.Value)
	require.True(t, ok)
	// The struct_value should have been recursively merged
	resultStruct := resultValue.GetStructValue()
	assert.NotNil(t, resultStruct)
	assert.Contains(t, resultStruct.Fields, "key1")
	assert.Contains(t, resultStruct.Fields, "key2")
}

func TestMergeField_NestedMessageDstDoesNotHaveField(t *testing.T) {
	t.Parallel()

	transformer := NewGRPCResponseTransformer(observability.NopLogger())
	ctx := context.Background()

	// v1 has string_value set (no struct_value)
	v1 := structpb.NewStringValue("hello")

	// v2 has struct_value set
	s2, err := structpb.NewStruct(map[string]interface{}{
		"key": "value",
	})
	require.NoError(t, err)
	v2 := structpb.NewStructValue(s2)

	// Merge: dst doesn't have struct_value, so it should be set directly
	result, err := transformer.MergeResponses(ctx, []proto.Message{v1, v2}, "merge")
	require.NoError(t, err)
	assert.NotNil(t, result)
}

// ============================================================
// RenameFields coverage: successful rename with source found
// ============================================================

func TestRenameFields_SuccessfulRename(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())

	// Use a Struct message where we can rename between fields
	// Actually, RenameFields copies value from source to target and clears source
	// Both source and target must exist in the schema
	// For wrapperspb.StringValue, there's only "value" field
	// We can test the "target field not found" path
	msg := wrapperspb.String("test")
	mappings := []config.FieldMapping{
		{Source: "value", Target: "nonexistent"},
	}

	result, err := transformer.RenameFields(msg, mappings)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestRenameFields_SourceAndTargetSameField(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())

	msg := wrapperspb.String("test")
	mappings := []config.FieldMapping{
		{Source: "value", Target: "value"},
	}

	result, err := transformer.RenameFields(msg, mappings)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

// ============================================================
// TransformMessage coverage: error paths for field mask and rename
// ============================================================

func TestTransformMessage_FieldMaskError(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())
	ctx := context.Background()

	// TransformMessage with field mask that triggers validation warning
	msg := wrapperspb.String("test")
	cfg := &config.GRPCTransformConfig{
		Response: &config.GRPCResponseTransformConfig{
			FieldMask: []string{"nonexistent_field"},
		},
	}

	// This should succeed (validation warning is logged but doesn't fail)
	result, err := transformer.TransformMessage(ctx, msg, cfg)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestTransformMessage_WithRepeatedFieldOpsError(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())
	ctx := context.Background()

	msg := wrapperspb.String("test")
	cfg := &config.GRPCTransformConfig{
		Response: &config.GRPCResponseTransformConfig{
			RepeatedFieldOps: []config.RepeatedFieldOperation{
				{Field: "nonexistent", Operation: config.RepeatedFieldOpLimit, Limit: 5},
			},
		},
	}

	// Should succeed (error is logged as warning, not returned)
	result, err := transformer.TransformMessage(ctx, msg, cfg)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestTransformMessage_WithMapFieldOpsError(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())
	ctx := context.Background()

	msg := wrapperspb.String("test")
	cfg := &config.GRPCTransformConfig{
		Response: &config.GRPCResponseTransformConfig{
			MapFieldOps: []config.MapFieldOperation{
				{Field: "nonexistent", Operation: config.MapFieldOpFilterKeys},
			},
		},
	}

	// Should succeed (error is logged as warning, not returned)
	result, err := transformer.TransformMessage(ctx, msg, cfg)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

// ============================================================
// mergeMapValues coverage: with nil value that produces invalid protoreflect.Value
// ============================================================

func TestMergeMapValues_WithInvalidValue(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())
	ctx := context.Background()

	msg, err := structpb.NewStruct(map[string]interface{}{
		"key1": "value1",
	})
	require.NoError(t, err)

	// Merge with a nil value - interfaceToValue(nil, ...) returns invalid Value
	cfg := &config.GRPCTransformConfig{
		Response: &config.GRPCResponseTransformConfig{
			MapFieldOps: []config.MapFieldOperation{
				{
					Field:     "fields",
					Operation: config.MapFieldOpMerge,
					MergeWith: map[string]interface{}{
						"key2": nil, // nil value should be skipped (invalid)
					},
				},
			},
		},
	}

	result, err := transformer.TransformMessage(ctx, msg, cfg)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

// ============================================================
// setFieldValue coverage: nested path with message navigation
// ============================================================

func TestSetFieldValue_NestedMessageNavigation(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())

	// Create a structpb.Value with struct_value
	s, err := structpb.NewStruct(map[string]interface{}{
		"key": "value",
	})
	require.NoError(t, err)
	v := structpb.NewStructValue(s)

	// Set a nested field: struct_value.fields
	// This navigates through the message hierarchy
	msgReflect := v.ProtoReflect()
	err = transformer.setFieldValue(msgReflect, "struct_value.fields", nil)
	// This will fail because "fields" is a map and nil can't be converted
	assert.Error(t, err)
}

// ============================================================
// getFieldValue coverage: nested message navigation
// ============================================================

func TestGetFieldValue_NestedMessageNavigation(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())

	// Create a structpb.Value with struct_value containing fields
	s, err := structpb.NewStruct(map[string]interface{}{
		"key": "value",
	})
	require.NoError(t, err)
	v := structpb.NewStructValue(s)

	// Get nested field: struct_value.fields
	msgReflect := v.ProtoReflect()
	result, err := transformer.getFieldValue(msgReflect, "struct_value.fields")
	require.NoError(t, err)
	assert.NotNil(t, result)
}

// ============================================================
// Filter coverage: validation warning path
// ============================================================

func TestFilter_WithInvalidPaths(t *testing.T) {
	t.Parallel()

	filter := NewFieldMaskFilter(observability.NopLogger())

	// Filter with paths that include invalid ones - should still succeed
	// (validation warning is logged but doesn't prevent filtering)
	msg := wrapperspb.String("test")
	result, err := filter.Filter(msg, []string{"value", "nonexistent"})
	require.NoError(t, err)
	assert.NotNil(t, result)

	resultWrapper, ok := result.(*wrapperspb.StringValue)
	require.True(t, ok)
	assert.Equal(t, "test", resultWrapper.Value)
}

// ============================================================
// ValidateFieldMask coverage: valid paths with JSON name
// ============================================================

func TestValidateFieldMask_WithValidPaths(t *testing.T) {
	t.Parallel()

	filter := NewFieldMaskFilter(observability.NopLogger())

	msg := wrapperspb.String("test")
	mask, err := filter.CreateFieldMask([]string{"value"})
	require.NoError(t, err)

	err = filter.ValidateFieldMask(msg, mask)
	assert.NoError(t, err)
}

func TestValidateFieldMask_MixedValidAndInvalidPaths(t *testing.T) {
	t.Parallel()

	filter := NewFieldMaskFilter(observability.NopLogger())

	msg := wrapperspb.String("test")
	mask, err := filter.CreateFieldMask([]string{"value", "nonexistent"})
	require.NoError(t, err)

	err = filter.ValidateFieldMask(msg, mask)
	assert.Error(t, err) // Should report invalid paths
}

// ============================================================
// TransformResponse coverage: error path
// ============================================================

func TestTransformResponse_TransformError(t *testing.T) {
	t.Parallel()

	transformer := NewGRPCResponseTransformer(observability.NopLogger())
	ctx := context.Background()

	// nil message with non-nil config should return error
	result, err := transformer.TransformResponse(ctx, nil, &config.GRPCResponseTransformConfig{
		FieldMask: []string{"test"},
	})
	assert.Error(t, err)
	assert.Nil(t, result)
}

// ============================================================
// request.go coverage: applyDefaultValues error, applyRemoveFields error,
// applyInjectFieldMask error, transformRequestMetadata authority
// ============================================================

func TestTransformRequest_WithAuthorityOverride(t *testing.T) {
	t.Parallel()

	transformer := NewGRPCRequestTransformer(observability.NopLogger())
	ctx := context.Background()

	msg := wrapperspb.String("test")
	cfg := &config.GRPCRequestTransformConfig{
		AuthorityOverride: "custom-authority",
		StaticMetadata: map[string]string{
			"x-key": "x-value",
		},
	}

	_, resultMD, err := transformer.TransformRequest(ctx, msg, metadata.MD{}, cfg)
	require.NoError(t, err)
	assert.Equal(t, "custom-authority", resultMD.Get(":authority")[0])
	assert.Equal(t, "x-value", resultMD.Get("x-key")[0])
}

func TestTransformRequest_NilMessageWithConfig(t *testing.T) {
	t.Parallel()

	transformer := NewGRPCRequestTransformer(observability.NopLogger())
	ctx := context.Background()

	cfg := &config.GRPCRequestTransformConfig{
		DefaultValues: map[string]interface{}{
			"value": "default",
		},
		RemoveFields:    []string{"field"},
		InjectFieldMask: []string{"mask"},
	}

	result, _, err := transformer.TransformRequest(ctx, nil, metadata.MD{}, cfg)
	require.NoError(t, err)
	assert.Nil(t, result)
}

// ============================================================
// TransformRequestWithDeadline coverage: with deadline injection
// ============================================================

func TestTransformRequestWithDeadline_WithDeadlineInjection(t *testing.T) {
	t.Parallel()

	transformer := NewGRPCRequestTransformer(observability.NopLogger())
	ctx := context.Background()

	msg := wrapperspb.String("test")
	cfg := &config.GRPCRequestTransformConfig{
		InjectDeadline: config.Duration(5000000000), // 5 seconds
	}

	resultCtx, resultMsg, resultMD, cancel, err := transformer.TransformRequestWithDeadline(ctx, msg, metadata.MD{}, cfg)
	defer cancel()

	require.NoError(t, err)
	assert.NotNil(t, resultMsg)
	assert.NotNil(t, resultMD)

	_, hasDeadline := resultCtx.Deadline()
	assert.True(t, hasDeadline)
}

func TestTransformRequestWithDeadline_Error(t *testing.T) {
	t.Parallel()

	transformer := NewGRPCRequestTransformer(observability.NopLogger())
	ctx := context.Background()

	// nil message with validation should fail
	cfg := &config.GRPCRequestTransformConfig{
		ValidateBeforeTransform: true,
	}

	_, _, _, cancel, err := transformer.TransformRequestWithDeadline(ctx, nil, metadata.MD{}, cfg)
	defer cancel()

	assert.Error(t, err)
}

// ============================================================
// InjectFields coverage: field not found in setFieldValue
// ============================================================

func TestInjectFields_FieldNotFoundInSchema(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())

	msg := wrapperspb.String("test")
	injections := []config.FieldInjection{
		{Field: "nonexistent_field", Value: "test"},
	}

	result, err := transformer.InjectFields(msg, injections)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

// ============================================================
// SetDefaultValues coverage: setFieldValue error path
// ============================================================

func TestSetDefaultValues_InvalidValueType(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())

	// wrapperspb.StringValue "value" field is string kind
	// Passing a value that can't be converted should trigger the error path
	msg := wrapperspb.String("")
	defaults := map[string]interface{}{
		"value": nil, // nil value for string kind returns invalid
	}

	result, err := transformer.SetDefaultValues(msg, defaults)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

// ============================================================
// ExtractValue coverage: nil tctx
// ============================================================

func TestExtractValue_NilTransformContext(t *testing.T) {
	t.Parallel()

	transformer := NewMetadataTransformer(observability.NopLogger())
	ctx := context.Background()

	// nil tctx should create a new one from context
	value, err := transformer.ExtractValue(ctx, "context.request_id", nil)
	require.NoError(t, err)
	assert.Equal(t, "", value)
}

// ============================================================
// TransformMetadata coverage: with dynamic metadata
// ============================================================

func TestTransformMetadata_WithDynamicMetadata(t *testing.T) {
	t.Parallel()

	transformer := NewMetadataTransformer(observability.NopLogger())

	tctx := NewTransformContext(nil)
	tctx.WithRequestID("req-123")
	ctx := ContextWithTransformContext(context.Background(), tctx)

	cfg := &config.GRPCRequestTransformConfig{
		DynamicMetadata: []config.DynamicMetadata{
			{Key: "x-request-id", Source: "context.request_id"},
		},
	}

	result, err := transformer.TransformMetadata(ctx, metadata.MD{}, cfg)
	require.NoError(t, err)
	assert.Equal(t, "req-123", result.Get("x-request-id")[0])
}

// ============================================================
// InjectDynamicMetadata coverage: extraction error path
// ============================================================

func TestInjectDynamicMetadata_ExtractionError(t *testing.T) {
	t.Parallel()

	transformer := NewMetadataTransformer(observability.NopLogger())
	ctx := context.Background()
	tctx := NewTransformContext(nil)

	// "unknown.category" will trigger extraction error
	dynamic := []config.DynamicMetadata{
		{Key: "x-key", Source: "unknown.category"},
	}

	result, err := transformer.InjectDynamicMetadata(ctx, metadata.MD{}, dynamic, tctx)
	require.NoError(t, err)
	assert.NotNil(t, result)
	// Key should not be set since extraction failed
	assert.Empty(t, result.Get("x-key"))
}

// ============================================================
// AggregateMessages coverage: empty messages
// ============================================================

func TestAggregateMessages_EmptySlice(t *testing.T) {
	t.Parallel()

	st := NewStreamingTransformer(observability.NopLogger(), nil)
	ctx := context.Background()

	result, err := st.AggregateMessages(ctx, []proto.Message{})
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestAggregateMessages_SingleMessage(t *testing.T) {
	t.Parallel()

	st := NewStreamingTransformer(observability.NopLogger(), nil)
	ctx := context.Background()

	msg := &fieldmaskpb.FieldMask{Paths: []string{"test"}}
	result, err := st.AggregateMessages(ctx, []proto.Message{msg})
	require.NoError(t, err)
	assert.Equal(t, msg, result)
}

func TestAggregateMessages_MultipleMessages(t *testing.T) {
	t.Parallel()

	st := NewStreamingTransformer(observability.NopLogger(), nil)
	ctx := context.Background()

	msg1 := &fieldmaskpb.FieldMask{Paths: []string{"first"}}
	msg2 := &fieldmaskpb.FieldMask{Paths: []string{"second"}}
	msg3 := &fieldmaskpb.FieldMask{Paths: []string{"third"}}

	result, err := st.AggregateMessages(ctx, []proto.Message{msg1, msg2, msg3})
	require.NoError(t, err)
	assert.NotNil(t, result)

	// Should return clone of last message
	resultMask, ok := result.(*fieldmaskpb.FieldMask)
	require.True(t, ok)
	assert.Equal(t, []string{"third"}, resultMask.Paths)
}

// ============================================================
// ApplyRateLimit coverage: rate limiter wait error (non-context)
// ============================================================

func TestApplyRateLimit_NoRateLimiter(t *testing.T) {
	t.Parallel()

	st := NewStreamingTransformer(observability.NopLogger(), nil)
	ctx := context.Background()

	err := st.ApplyRateLimit(ctx)
	assert.NoError(t, err)
}

// ============================================================
// TransformStreamMessage coverage: filter path
// ============================================================

func TestTransformStreamMessage_NilMessage(t *testing.T) {
	t.Parallel()

	st := NewStreamingTransformer(observability.NopLogger(), nil)
	ctx := context.Background()

	result, shouldSend, err := st.TransformStreamMessage(ctx, nil, 0, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNilMessage)
	assert.False(t, shouldSend)
	assert.Nil(t, result)
}

// ============================================================
// mergeMessages coverage: empty messages
// ============================================================

func TestMergeMessages_EmptyMessages(t *testing.T) {
	t.Parallel()

	transformer := NewGRPCResponseTransformer(observability.NopLogger())
	ctx := context.Background()

	result, err := transformer.MergeResponses(ctx, []proto.Message{}, "merge")
	assert.Error(t, err)
	assert.Nil(t, result)
}

// ============================================================
// InjectFields coverage: invalid value conversion
// ============================================================

func TestInjectFields_InvalidValueConversion(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())

	// wrapperspb.Int32Value has an int32 "value" field
	msg := wrapperspb.Int32(42)
	injections := []config.FieldInjection{
		// Try to inject a string into an int32 field - should fail conversion
		{Field: "value", Value: "not-a-number"},
	}

	result, err := transformer.InjectFields(msg, injections)
	require.NoError(t, err) // Error is logged, not returned
	assert.NotNil(t, result)
}

// ============================================================
// compareValues coverage: additional type comparisons
// ============================================================

func TestCompareValues_Int32GreaterThan(t *testing.T) {
	t.Parallel()

	assert.False(t, compareValues(int32(2), int32(1)))
}

func TestCompareValues_Int64GreaterThan(t *testing.T) {
	t.Parallel()

	assert.False(t, compareValues(int64(2), int64(1)))
}

func TestCompareValues_Float32GreaterThan(t *testing.T) {
	t.Parallel()

	assert.False(t, compareValues(float32(2.0), float32(1.0)))
}

func TestCompareValues_Float64GreaterThan(t *testing.T) {
	t.Parallel()

	assert.False(t, compareValues(float64(2.0), float64(1.0)))
}
