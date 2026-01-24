// Package transform provides gRPC-specific data transformation capabilities.
package transform

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestNewProtobufTransformer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		logger observability.Logger
	}{
		{
			name:   "with logger",
			logger: observability.NopLogger(),
		},
		{
			name:   "nil logger",
			logger: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			transformer := NewProtobufTransformer(tt.logger)
			require.NotNil(t, transformer)
			assert.NotNil(t, transformer.logger)
			assert.NotNil(t, transformer.fieldMaskFilter)
		})
	}
}

func TestProtobufTransformer_TransformMessage_NilMessage(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())
	cfg := &config.GRPCTransformConfig{}

	result, err := transformer.TransformMessage(context.Background(), nil, cfg)

	assert.ErrorIs(t, err, ErrNilMessage)
	assert.Nil(t, result)
}

func TestProtobufTransformer_TransformMessage_NilConfig(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())
	msg := wrapperspb.String("test")

	result, err := transformer.TransformMessage(context.Background(), msg, nil)

	require.NoError(t, err)
	assert.Equal(t, msg, result)
}

func TestProtobufTransformer_TransformMessage_NilResponseConfig(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())
	msg := wrapperspb.String("test")
	cfg := &config.GRPCTransformConfig{Response: nil}

	result, err := transformer.TransformMessage(context.Background(), msg, cfg)

	require.NoError(t, err)
	assert.Equal(t, msg, result)
}

func TestProtobufTransformer_TransformMessage_WithFieldMask(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())

	// Create a Struct message with multiple fields
	msg, err := structpb.NewStruct(map[string]interface{}{
		"name":  "John",
		"email": "john@example.com",
		"age":   30,
	})
	require.NoError(t, err)

	cfg := &config.GRPCTransformConfig{
		Response: &config.GRPCResponseTransformConfig{
			FieldMask: []string{"fields"},
		},
	}

	result, err := transformer.TransformMessage(context.Background(), msg, cfg)

	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestProtobufTransformer_ApplyFieldMask_NilMessage(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())

	result, err := transformer.ApplyFieldMask(nil, []string{"name"})

	assert.ErrorIs(t, err, ErrNilMessage)
	assert.Nil(t, result)
}

func TestProtobufTransformer_ApplyFieldMask_EmptyPaths(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())
	msg := wrapperspb.String("test")

	result, err := transformer.ApplyFieldMask(msg, []string{})

	require.NoError(t, err)
	assert.Equal(t, msg, result)
}

func TestProtobufTransformer_ApplyFieldMask_NilPaths(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())
	msg := wrapperspb.String("test")

	result, err := transformer.ApplyFieldMask(msg, nil)

	require.NoError(t, err)
	assert.Equal(t, msg, result)
}

func TestProtobufTransformer_RenameFields_NilMessage(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())
	mappings := []config.FieldMapping{{Source: "old", Target: "new"}}

	result, err := transformer.RenameFields(nil, mappings)

	assert.ErrorIs(t, err, ErrNilMessage)
	assert.Nil(t, result)
}

func TestProtobufTransformer_RenameFields_EmptyMappings(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())
	msg := wrapperspb.String("test")

	result, err := transformer.RenameFields(msg, []config.FieldMapping{})

	require.NoError(t, err)
	assert.Equal(t, msg, result)
}

func TestProtobufTransformer_RenameFields_NilMappings(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())
	msg := wrapperspb.String("test")

	result, err := transformer.RenameFields(msg, nil)

	require.NoError(t, err)
	assert.Equal(t, msg, result)
}

func TestProtobufTransformer_RenameFields_EmptySourceOrTarget(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())
	msg := wrapperspb.String("test")

	mappings := []config.FieldMapping{
		{Source: "", Target: "new"},
		{Source: "old", Target: ""},
		{Source: "", Target: ""},
	}

	result, err := transformer.RenameFields(msg, mappings)

	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestProtobufTransformer_RenameFields_SourceNotFound(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())
	msg := wrapperspb.String("test")

	mappings := []config.FieldMapping{
		{Source: "nonexistent", Target: "value"},
	}

	result, err := transformer.RenameFields(msg, mappings)

	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestProtobufTransformer_TransformRepeatedField_NilMessage(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())
	op := config.RepeatedFieldOperation{Field: "items", Operation: config.RepeatedFieldOpLimit}

	result, err := transformer.TransformRepeatedField(nil, op)

	assert.ErrorIs(t, err, ErrNilMessage)
	assert.Nil(t, result)
}

func TestProtobufTransformer_TransformRepeatedField_EmptyField(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())
	msg := wrapperspb.String("test")
	op := config.RepeatedFieldOperation{Field: "", Operation: config.RepeatedFieldOpLimit}

	result, err := transformer.TransformRepeatedField(msg, op)

	require.NoError(t, err)
	assert.Equal(t, msg, result)
}

func TestProtobufTransformer_TransformRepeatedField_FieldNotFound(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())
	msg := wrapperspb.String("test")
	op := config.RepeatedFieldOperation{Field: "nonexistent", Operation: config.RepeatedFieldOpLimit}

	result, err := transformer.TransformRepeatedField(msg, op)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "field not found")
	require.NotNil(t, result)
}

func TestProtobufTransformer_TransformRepeatedField_NotRepeatedField(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())
	msg := wrapperspb.String("test")
	op := config.RepeatedFieldOperation{Field: "value", Operation: config.RepeatedFieldOpLimit}

	result, err := transformer.TransformRepeatedField(msg, op)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a repeated field")
	require.NotNil(t, result)
}

func TestProtobufTransformer_TransformRepeatedField_UnknownOperation(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())

	// Use FieldMask which has a repeated "paths" field
	msg := &fieldmaskpb.FieldMask{Paths: []string{"a", "b", "c"}}
	op := config.RepeatedFieldOperation{Field: "paths", Operation: "unknown"}

	result, err := transformer.TransformRepeatedField(msg, op)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown operation")
	require.NotNil(t, result)
}

func TestProtobufTransformer_TransformRepeatedField_Limit(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())

	msg := &fieldmaskpb.FieldMask{Paths: []string{"a", "b", "c", "d", "e"}}
	op := config.RepeatedFieldOperation{
		Field:     "paths",
		Operation: config.RepeatedFieldOpLimit,
		Limit:     3,
	}

	result, err := transformer.TransformRepeatedField(msg, op)

	require.NoError(t, err)
	require.NotNil(t, result)

	resultMask, ok := result.(*fieldmaskpb.FieldMask)
	require.True(t, ok)
	assert.Len(t, resultMask.Paths, 3)
}

func TestProtobufTransformer_TransformRepeatedField_LimitZero(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())

	msg := &fieldmaskpb.FieldMask{Paths: []string{"a", "b", "c"}}
	op := config.RepeatedFieldOperation{
		Field:     "paths",
		Operation: config.RepeatedFieldOpLimit,
		Limit:     0,
	}

	result, err := transformer.TransformRepeatedField(msg, op)

	require.NoError(t, err)
	require.NotNil(t, result)

	resultMask, ok := result.(*fieldmaskpb.FieldMask)
	require.True(t, ok)
	// Limit 0 should not change the list
	assert.Len(t, resultMask.Paths, 3)
}

func TestProtobufTransformer_TransformRepeatedField_LimitLargerThanList(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())

	msg := &fieldmaskpb.FieldMask{Paths: []string{"a", "b"}}
	op := config.RepeatedFieldOperation{
		Field:     "paths",
		Operation: config.RepeatedFieldOpLimit,
		Limit:     10,
	}

	result, err := transformer.TransformRepeatedField(msg, op)

	require.NoError(t, err)
	require.NotNil(t, result)

	resultMask, ok := result.(*fieldmaskpb.FieldMask)
	require.True(t, ok)
	assert.Len(t, resultMask.Paths, 2)
}

func TestProtobufTransformer_TransformRepeatedField_Sort(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())

	msg := &fieldmaskpb.FieldMask{Paths: []string{"c", "a", "b"}}
	op := config.RepeatedFieldOperation{
		Field:     "paths",
		Operation: config.RepeatedFieldOpSort,
		SortOrder: config.SortOrderAsc,
	}

	result, err := transformer.TransformRepeatedField(msg, op)

	require.NoError(t, err)
	require.NotNil(t, result)

	resultMask, ok := result.(*fieldmaskpb.FieldMask)
	require.True(t, ok)
	assert.Equal(t, []string{"a", "b", "c"}, resultMask.Paths)
}

func TestProtobufTransformer_TransformRepeatedField_SortDesc(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())

	msg := &fieldmaskpb.FieldMask{Paths: []string{"a", "c", "b"}}
	op := config.RepeatedFieldOperation{
		Field:     "paths",
		Operation: config.RepeatedFieldOpSort,
		SortOrder: config.SortOrderDesc,
	}

	result, err := transformer.TransformRepeatedField(msg, op)

	require.NoError(t, err)
	require.NotNil(t, result)

	resultMask, ok := result.(*fieldmaskpb.FieldMask)
	require.True(t, ok)
	assert.Equal(t, []string{"c", "b", "a"}, resultMask.Paths)
}

func TestProtobufTransformer_TransformRepeatedField_SortSingleElement(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())

	msg := &fieldmaskpb.FieldMask{Paths: []string{"a"}}
	op := config.RepeatedFieldOperation{
		Field:     "paths",
		Operation: config.RepeatedFieldOpSort,
		SortOrder: config.SortOrderAsc,
	}

	result, err := transformer.TransformRepeatedField(msg, op)

	require.NoError(t, err)
	require.NotNil(t, result)

	resultMask, ok := result.(*fieldmaskpb.FieldMask)
	require.True(t, ok)
	assert.Equal(t, []string{"a"}, resultMask.Paths)
}

func TestProtobufTransformer_TransformRepeatedField_Deduplicate(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())

	msg := &fieldmaskpb.FieldMask{Paths: []string{"a", "b", "a", "c", "b"}}
	op := config.RepeatedFieldOperation{
		Field:     "paths",
		Operation: config.RepeatedFieldOpDeduplicate,
	}

	result, err := transformer.TransformRepeatedField(msg, op)

	require.NoError(t, err)
	require.NotNil(t, result)

	resultMask, ok := result.(*fieldmaskpb.FieldMask)
	require.True(t, ok)
	assert.Len(t, resultMask.Paths, 3)
	assert.Contains(t, resultMask.Paths, "a")
	assert.Contains(t, resultMask.Paths, "b")
	assert.Contains(t, resultMask.Paths, "c")
}

func TestProtobufTransformer_TransformRepeatedField_DeduplicateSingleElement(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())

	msg := &fieldmaskpb.FieldMask{Paths: []string{"a"}}
	op := config.RepeatedFieldOperation{
		Field:     "paths",
		Operation: config.RepeatedFieldOpDeduplicate,
	}

	result, err := transformer.TransformRepeatedField(msg, op)

	require.NoError(t, err)
	require.NotNil(t, result)

	resultMask, ok := result.(*fieldmaskpb.FieldMask)
	require.True(t, ok)
	assert.Equal(t, []string{"a"}, resultMask.Paths)
}

func TestProtobufTransformer_TransformRepeatedField_Filter(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())

	msg := &fieldmaskpb.FieldMask{Paths: []string{"a", "b", "c"}}
	op := config.RepeatedFieldOperation{
		Field:     "paths",
		Operation: config.RepeatedFieldOpFilter,
		Condition: "value != 'b'",
	}

	result, err := transformer.TransformRepeatedField(msg, op)

	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestProtobufTransformer_TransformRepeatedField_FilterEmptyCondition(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())

	msg := &fieldmaskpb.FieldMask{Paths: []string{"a", "b", "c"}}
	op := config.RepeatedFieldOperation{
		Field:     "paths",
		Operation: config.RepeatedFieldOpFilter,
		Condition: "",
	}

	result, err := transformer.TransformRepeatedField(msg, op)

	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestProtobufTransformer_TransformMapField_NilMessage(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())
	op := config.MapFieldOperation{Field: "fields", Operation: config.MapFieldOpFilterKeys}

	result, err := transformer.TransformMapField(nil, op)

	assert.ErrorIs(t, err, ErrNilMessage)
	assert.Nil(t, result)
}

func TestProtobufTransformer_TransformMapField_EmptyField(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())
	msg := wrapperspb.String("test")
	op := config.MapFieldOperation{Field: "", Operation: config.MapFieldOpFilterKeys}

	result, err := transformer.TransformMapField(msg, op)

	require.NoError(t, err)
	assert.Equal(t, msg, result)
}

func TestProtobufTransformer_TransformMapField_FieldNotFound(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())
	msg := wrapperspb.String("test")
	op := config.MapFieldOperation{Field: "nonexistent", Operation: config.MapFieldOpFilterKeys}

	result, err := transformer.TransformMapField(msg, op)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "field not found")
	require.NotNil(t, result)
}

func TestProtobufTransformer_TransformMapField_NotMapField(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())
	msg := wrapperspb.String("test")
	op := config.MapFieldOperation{Field: "value", Operation: config.MapFieldOpFilterKeys}

	result, err := transformer.TransformMapField(msg, op)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a map field")
	require.NotNil(t, result)
}

func TestProtobufTransformer_TransformMapField_UnknownOperation(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())

	// Use Struct which has a map "fields" field
	msg, err := structpb.NewStruct(map[string]interface{}{
		"key1": "value1",
		"key2": "value2",
	})
	require.NoError(t, err)

	op := config.MapFieldOperation{Field: "fields", Operation: "unknown"}

	result, err := transformer.TransformMapField(msg, op)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown operation")
	require.NotNil(t, result)
}

func TestProtobufTransformer_TransformMapField_FilterKeys_AllowList(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())

	msg, err := structpb.NewStruct(map[string]interface{}{
		"key1": "value1",
		"key2": "value2",
		"key3": "value3",
	})
	require.NoError(t, err)

	op := config.MapFieldOperation{
		Field:     "fields",
		Operation: config.MapFieldOpFilterKeys,
		AllowKeys: []string{"key1", "key3"},
	}

	result, err := transformer.TransformMapField(msg, op)

	require.NoError(t, err)
	require.NotNil(t, result)

	resultStruct, ok := result.(*structpb.Struct)
	require.True(t, ok)
	assert.Len(t, resultStruct.Fields, 2)
	assert.Contains(t, resultStruct.Fields, "key1")
	assert.Contains(t, resultStruct.Fields, "key3")
	assert.NotContains(t, resultStruct.Fields, "key2")
}

func TestProtobufTransformer_TransformMapField_FilterKeys_DenyList(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())

	msg, err := structpb.NewStruct(map[string]interface{}{
		"key1": "value1",
		"key2": "value2",
		"key3": "value3",
	})
	require.NoError(t, err)

	op := config.MapFieldOperation{
		Field:     "fields",
		Operation: config.MapFieldOpFilterKeys,
		DenyKeys:  []string{"key2"},
	}

	result, err := transformer.TransformMapField(msg, op)

	require.NoError(t, err)
	require.NotNil(t, result)

	resultStruct, ok := result.(*structpb.Struct)
	require.True(t, ok)
	assert.Len(t, resultStruct.Fields, 2)
	assert.Contains(t, resultStruct.Fields, "key1")
	assert.Contains(t, resultStruct.Fields, "key3")
	assert.NotContains(t, resultStruct.Fields, "key2")
}

func TestProtobufTransformer_TransformMapField_Merge(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())

	msg, err := structpb.NewStruct(map[string]interface{}{
		"key1": "value1",
	})
	require.NoError(t, err)

	op := config.MapFieldOperation{
		Field:     "fields",
		Operation: config.MapFieldOpMerge,
		MergeWith: map[string]interface{}{
			"key2": "value2",
		},
	}

	result, err := transformer.TransformMapField(msg, op)

	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestProtobufTransformer_TransformMapField_MergeEmpty(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())

	msg, err := structpb.NewStruct(map[string]interface{}{
		"key1": "value1",
	})
	require.NoError(t, err)

	op := config.MapFieldOperation{
		Field:     "fields",
		Operation: config.MapFieldOpMerge,
		MergeWith: map[string]interface{}{},
	}

	result, err := transformer.TransformMapField(msg, op)

	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestProtobufTransformer_InjectFields_NilMessage(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())
	injections := []config.FieldInjection{{Field: "name", Value: "test"}}

	result, err := transformer.InjectFields(nil, injections)

	assert.ErrorIs(t, err, ErrNilMessage)
	assert.Nil(t, result)
}

func TestProtobufTransformer_InjectFields_EmptyInjections(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())
	msg := wrapperspb.String("test")

	result, err := transformer.InjectFields(msg, []config.FieldInjection{})

	require.NoError(t, err)
	assert.Equal(t, msg, result)
}

func TestProtobufTransformer_InjectFields_NilInjections(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())
	msg := wrapperspb.String("test")

	result, err := transformer.InjectFields(msg, nil)

	require.NoError(t, err)
	assert.Equal(t, msg, result)
}

func TestProtobufTransformer_InjectFields_EmptyFieldName(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())
	msg := wrapperspb.String("test")

	injections := []config.FieldInjection{
		{Field: "", Value: "test"},
	}

	result, err := transformer.InjectFields(msg, injections)

	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestProtobufTransformer_InjectFields_WithSource(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())
	msg := wrapperspb.String("test")

	injections := []config.FieldInjection{
		{Field: "value", Source: "jwt.claim.sub"},
	}

	result, err := transformer.InjectFields(msg, injections)

	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestProtobufTransformer_InjectFields_WithValue(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())
	msg := wrapperspb.String("original")

	injections := []config.FieldInjection{
		{Field: "value", Value: "injected"},
	}

	result, err := transformer.InjectFields(msg, injections)

	require.NoError(t, err)
	require.NotNil(t, result)

	resultWrapper, ok := result.(*wrapperspb.StringValue)
	require.True(t, ok)
	assert.Equal(t, "injected", resultWrapper.Value)
}

func TestProtobufTransformer_RemoveFields_NilMessage(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())

	result, err := transformer.RemoveFields(nil, []string{"name"})

	assert.ErrorIs(t, err, ErrNilMessage)
	assert.Nil(t, result)
}

func TestProtobufTransformer_RemoveFields_EmptyFields(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())
	msg := wrapperspb.String("test")

	result, err := transformer.RemoveFields(msg, []string{})

	require.NoError(t, err)
	assert.Equal(t, msg, result)
}

func TestProtobufTransformer_RemoveFields_NilFields(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())
	msg := wrapperspb.String("test")

	result, err := transformer.RemoveFields(msg, nil)

	require.NoError(t, err)
	assert.Equal(t, msg, result)
}

func TestProtobufTransformer_RemoveFields_ExistingField(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())
	msg := wrapperspb.String("test")

	result, err := transformer.RemoveFields(msg, []string{"value"})

	require.NoError(t, err)
	require.NotNil(t, result)

	resultWrapper, ok := result.(*wrapperspb.StringValue)
	require.True(t, ok)
	assert.Empty(t, resultWrapper.Value)
}

func TestProtobufTransformer_RemoveFields_NonexistentField(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())
	msg := wrapperspb.String("test")

	result, err := transformer.RemoveFields(msg, []string{"nonexistent"})

	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestProtobufTransformer_SetDefaultValues_NilMessage(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())
	defaults := map[string]interface{}{"name": "default"}

	result, err := transformer.SetDefaultValues(nil, defaults)

	assert.ErrorIs(t, err, ErrNilMessage)
	assert.Nil(t, result)
}

func TestProtobufTransformer_SetDefaultValues_EmptyDefaults(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())
	msg := wrapperspb.String("test")

	result, err := transformer.SetDefaultValues(msg, map[string]interface{}{})

	require.NoError(t, err)
	assert.Equal(t, msg, result)
}

func TestProtobufTransformer_SetDefaultValues_NilDefaults(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())
	msg := wrapperspb.String("test")

	result, err := transformer.SetDefaultValues(msg, nil)

	require.NoError(t, err)
	assert.Equal(t, msg, result)
}

func TestProtobufTransformer_SetDefaultValues_FieldAlreadySet(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())
	msg := wrapperspb.String("existing")

	defaults := map[string]interface{}{
		"value": "default",
	}

	result, err := transformer.SetDefaultValues(msg, defaults)

	require.NoError(t, err)
	require.NotNil(t, result)

	resultWrapper, ok := result.(*wrapperspb.StringValue)
	require.True(t, ok)
	// Should keep existing value
	assert.Equal(t, "existing", resultWrapper.Value)
}

func TestProtobufTransformer_SetDefaultValues_FieldNotSet(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())
	msg := wrapperspb.String("")

	defaults := map[string]interface{}{
		"value": "default",
	}

	result, err := transformer.SetDefaultValues(msg, defaults)

	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestProtobufTransformer_SetDefaultValues_NonexistentField(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())
	msg := wrapperspb.String("test")

	defaults := map[string]interface{}{
		"nonexistent": "default",
	}

	result, err := transformer.SetDefaultValues(msg, defaults)

	require.NoError(t, err)
	require.NotNil(t, result)
}

// Test helper functions

func TestValueToInterface(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		value    protoreflect.Value
		expected interface{}
	}{
		{
			name:     "invalid value",
			value:    protoreflect.Value{},
			expected: nil,
		},
		{
			name:     "string value",
			value:    protoreflect.ValueOfString("test"),
			expected: "test",
		},
		{
			name:     "int32 value",
			value:    protoreflect.ValueOfInt32(42),
			expected: int32(42),
		},
		{
			name:     "int64 value",
			value:    protoreflect.ValueOfInt64(42),
			expected: int64(42),
		},
		{
			name:     "float32 value",
			value:    protoreflect.ValueOfFloat32(3.14),
			expected: float32(3.14),
		},
		{
			name:     "float64 value",
			value:    protoreflect.ValueOfFloat64(3.14),
			expected: float64(3.14),
		},
		{
			name:     "bool value",
			value:    protoreflect.ValueOfBool(true),
			expected: true,
		},
		{
			name:     "bytes value",
			value:    protoreflect.ValueOfBytes([]byte("test")),
			expected: []byte("test"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := valueToInterface(tt.value)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestInterfaceToValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		value    interface{}
		kind     protoreflect.Kind
		expected interface{}
		valid    bool
	}{
		{
			name:     "nil value",
			value:    nil,
			kind:     protoreflect.StringKind,
			expected: nil,
			valid:    false,
		},
		{
			name:     "bool value",
			value:    true,
			kind:     protoreflect.BoolKind,
			expected: true,
			valid:    true,
		},
		{
			name:     "string value",
			value:    "test",
			kind:     protoreflect.StringKind,
			expected: "test",
			valid:    true,
		},
		{
			name:     "int to string",
			value:    42,
			kind:     protoreflect.StringKind,
			expected: "42",
			valid:    true,
		},
		{
			name:     "bytes from []byte",
			value:    []byte("test"),
			kind:     protoreflect.BytesKind,
			expected: []byte("test"),
			valid:    true,
		},
		{
			name:     "bytes from string",
			value:    "test",
			kind:     protoreflect.BytesKind,
			expected: []byte("test"),
			valid:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := interfaceToValue(tt.value, tt.kind)
			if tt.valid {
				assert.True(t, result.IsValid())
				assert.Equal(t, tt.expected, result.Interface())
			} else {
				assert.False(t, result.IsValid())
			}
		})
	}
}

func TestConvertToInt32(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		value    interface{}
		expected int32
		valid    bool
	}{
		{
			name:     "int value",
			value:    42,
			expected: 42,
			valid:    true,
		},
		{
			name:     "int32 value",
			value:    int32(42),
			expected: 42,
			valid:    true,
		},
		{
			name:     "int64 value in range",
			value:    int64(42),
			expected: 42,
			valid:    true,
		},
		{
			name:     "int64 value out of range",
			value:    int64(3000000000),
			expected: 0,
			valid:    false,
		},
		{
			name:     "float64 value in range",
			value:    float64(42.0),
			expected: 42,
			valid:    true,
		},
		{
			name:     "float64 value out of range",
			value:    float64(3000000000.0),
			expected: 0,
			valid:    false,
		},
		{
			name:     "string value",
			value:    "42",
			expected: 0,
			valid:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := convertToInt32(tt.value)
			if tt.valid {
				assert.True(t, result.IsValid())
				assert.Equal(t, tt.expected, result.Interface())
			} else {
				assert.False(t, result.IsValid())
			}
		})
	}
}

func TestConvertToInt64(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		value    interface{}
		expected int64
		valid    bool
	}{
		{
			name:     "int value",
			value:    42,
			expected: 42,
			valid:    true,
		},
		{
			name:     "int32 value",
			value:    int32(42),
			expected: 42,
			valid:    true,
		},
		{
			name:     "int64 value",
			value:    int64(42),
			expected: 42,
			valid:    true,
		},
		{
			name:     "float64 value",
			value:    float64(42.0),
			expected: 42,
			valid:    true,
		},
		{
			name:     "string value",
			value:    "42",
			expected: 0,
			valid:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := convertToInt64(tt.value)
			if tt.valid {
				assert.True(t, result.IsValid())
				assert.Equal(t, tt.expected, result.Interface())
			} else {
				assert.False(t, result.IsValid())
			}
		})
	}
}

func TestConvertToUint32(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		value    interface{}
		expected uint32
		valid    bool
	}{
		{
			name:     "uint value",
			value:    uint(42),
			expected: 42,
			valid:    true,
		},
		{
			name:     "uint32 value",
			value:    uint32(42),
			expected: 42,
			valid:    true,
		},
		{
			name:     "uint64 value in range",
			value:    uint64(42),
			expected: 42,
			valid:    true,
		},
		{
			name:     "uint64 value out of range",
			value:    uint64(5000000000),
			expected: 0,
			valid:    false,
		},
		{
			name:     "int value positive",
			value:    42,
			expected: 42,
			valid:    true,
		},
		{
			name:     "int value negative",
			value:    -42,
			expected: 0,
			valid:    false,
		},
		{
			name:     "float64 value positive",
			value:    float64(42.0),
			expected: 42,
			valid:    true,
		},
		{
			name:     "float64 value negative",
			value:    float64(-42.0),
			expected: 0,
			valid:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := convertToUint32(tt.value)
			if tt.valid {
				assert.True(t, result.IsValid())
				assert.Equal(t, tt.expected, result.Interface())
			} else {
				assert.False(t, result.IsValid())
			}
		})
	}
}

func TestConvertToUint64(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		value    interface{}
		expected uint64
		valid    bool
	}{
		{
			name:     "uint value",
			value:    uint(42),
			expected: 42,
			valid:    true,
		},
		{
			name:     "uint32 value",
			value:    uint32(42),
			expected: 42,
			valid:    true,
		},
		{
			name:     "uint64 value",
			value:    uint64(42),
			expected: 42,
			valid:    true,
		},
		{
			name:     "int value positive",
			value:    42,
			expected: 42,
			valid:    true,
		},
		{
			name:     "int value negative",
			value:    -42,
			expected: 0,
			valid:    false,
		},
		{
			name:     "float64 value positive",
			value:    float64(42.0),
			expected: 42,
			valid:    true,
		},
		{
			name:     "float64 value negative",
			value:    float64(-42.0),
			expected: 0,
			valid:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := convertToUint64(tt.value)
			if tt.valid {
				assert.True(t, result.IsValid())
				assert.Equal(t, tt.expected, result.Interface())
			} else {
				assert.False(t, result.IsValid())
			}
		})
	}
}

func TestConvertToFloat32(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		value    interface{}
		expected float32
		valid    bool
	}{
		{
			name:     "float32 value",
			value:    float32(3.14),
			expected: 3.14,
			valid:    true,
		},
		{
			name:     "float64 value",
			value:    float64(3.14),
			expected: float32(3.14),
			valid:    true,
		},
		{
			name:     "int value",
			value:    42,
			expected: 42.0,
			valid:    true,
		},
		{
			name:     "string value",
			value:    "3.14",
			expected: 0,
			valid:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := convertToFloat32(tt.value)
			if tt.valid {
				assert.True(t, result.IsValid())
				assert.InDelta(t, tt.expected, result.Interface(), 0.001)
			} else {
				assert.False(t, result.IsValid())
			}
		})
	}
}

func TestConvertToFloat64(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		value    interface{}
		expected float64
		valid    bool
	}{
		{
			name:     "float32 value",
			value:    float32(3.14),
			expected: float64(float32(3.14)),
			valid:    true,
		},
		{
			name:     "float64 value",
			value:    float64(3.14),
			expected: 3.14,
			valid:    true,
		},
		{
			name:     "int value",
			value:    42,
			expected: 42.0,
			valid:    true,
		},
		{
			name:     "string value",
			value:    "3.14",
			expected: 0,
			valid:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := convertToFloat64(tt.value)
			if tt.valid {
				assert.True(t, result.IsValid())
				assert.InDelta(t, tt.expected, result.Interface(), 0.001)
			} else {
				assert.False(t, result.IsValid())
			}
		})
	}
}

func TestCompareValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		a        interface{}
		b        interface{}
		expected bool
	}{
		{
			name:     "string less than",
			a:        "a",
			b:        "b",
			expected: true,
		},
		{
			name:     "string greater than",
			a:        "b",
			b:        "a",
			expected: false,
		},
		{
			name:     "string equal",
			a:        "a",
			b:        "a",
			expected: false,
		},
		{
			name:     "int less than",
			a:        1,
			b:        2,
			expected: true,
		},
		{
			name:     "int greater than",
			a:        2,
			b:        1,
			expected: false,
		},
		{
			name:     "int32 less than",
			a:        int32(1),
			b:        int32(2),
			expected: true,
		},
		{
			name:     "int64 less than",
			a:        int64(1),
			b:        int64(2),
			expected: true,
		},
		{
			name:     "float32 less than",
			a:        float32(1.0),
			b:        float32(2.0),
			expected: true,
		},
		{
			name:     "float64 less than",
			a:        float64(1.0),
			b:        float64(2.0),
			expected: true,
		},
		{
			name:     "mixed types fallback to string",
			a:        1,
			b:        "2",
			expected: true, // "1" < "2"
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := compareValues(tt.a, tt.b)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestProtobufTransformer_FindFieldDescriptor(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())
	msg := wrapperspb.String("test")
	desc := msg.ProtoReflect().Descriptor()

	tests := []struct {
		name      string
		fieldName string
		found     bool
	}{
		{
			name:      "exact name match",
			fieldName: "value",
			found:     true,
		},
		{
			name:      "case insensitive match",
			fieldName: "VALUE",
			found:     true,
		},
		{
			name:      "nonexistent field",
			fieldName: "nonexistent",
			found:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fd := transformer.findFieldDescriptor(desc, tt.fieldName)
			if tt.found {
				assert.NotNil(t, fd)
			} else {
				assert.Nil(t, fd)
			}
		})
	}
}

func TestProtobufTransformer_GetFieldValue(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())

	tests := []struct {
		name      string
		msg       proto.Message
		path      string
		expected  interface{}
		expectErr bool
	}{
		{
			name:      "simple field",
			msg:       wrapperspb.String("test"),
			path:      "value",
			expected:  "test",
			expectErr: false,
		},
		{
			name:      "nonexistent field",
			msg:       wrapperspb.String("test"),
			path:      "nonexistent",
			expected:  nil,
			expectErr: true,
		},
		{
			name:      "field not set",
			msg:       wrapperspb.String(""),
			path:      "value",
			expected:  nil,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result, err := transformer.getFieldValue(tt.msg.ProtoReflect(), tt.path)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestProtobufTransformer_SetFieldValue(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())

	tests := []struct {
		name      string
		msg       proto.Message
		path      string
		value     interface{}
		expectErr bool
	}{
		{
			name:      "set string field",
			msg:       wrapperspb.String("original"),
			path:      "value",
			value:     "new",
			expectErr: false,
		},
		{
			name:      "nonexistent field",
			msg:       wrapperspb.String("test"),
			path:      "nonexistent",
			value:     "value",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			msgClone := proto.Clone(tt.msg)
			err := transformer.setFieldValue(msgClone.ProtoReflect(), tt.path, tt.value)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestProtobufTransformer_ClearField(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())

	tests := []struct {
		name      string
		msg       proto.Message
		path      string
		expectErr bool
	}{
		{
			name:      "clear existing field",
			msg:       wrapperspb.String("test"),
			path:      "value",
			expectErr: false,
		},
		{
			name:      "nonexistent field",
			msg:       wrapperspb.String("test"),
			path:      "nonexistent",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			msgClone := proto.Clone(tt.msg)
			err := transformer.clearField(msgClone.ProtoReflect(), tt.path)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestProtobufTransformer_TransformMessage_WithFieldMappings(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())
	msg := wrapperspb.String("test")

	cfg := &config.GRPCTransformConfig{
		Response: &config.GRPCResponseTransformConfig{
			FieldMappings: []config.FieldMapping{
				{Source: "value", Target: "value"},
			},
		},
	}

	result, err := transformer.TransformMessage(context.Background(), msg, cfg)

	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestProtobufTransformer_TransformMessage_WithRepeatedFieldOps(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())
	msg := &fieldmaskpb.FieldMask{Paths: []string{"a", "b", "c"}}

	cfg := &config.GRPCTransformConfig{
		Response: &config.GRPCResponseTransformConfig{
			RepeatedFieldOps: []config.RepeatedFieldOperation{
				{Field: "paths", Operation: config.RepeatedFieldOpLimit, Limit: 2},
			},
		},
	}

	result, err := transformer.TransformMessage(context.Background(), msg, cfg)

	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestProtobufTransformer_TransformMessage_WithMapFieldOps(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())
	msg, err := structpb.NewStruct(map[string]interface{}{
		"key1": "value1",
		"key2": "value2",
	})
	require.NoError(t, err)

	cfg := &config.GRPCTransformConfig{
		Response: &config.GRPCResponseTransformConfig{
			MapFieldOps: []config.MapFieldOperation{
				{Field: "fields", Operation: config.MapFieldOpFilterKeys, AllowKeys: []string{"key1"}},
			},
		},
	}

	result, err := transformer.TransformMessage(context.Background(), msg, cfg)

	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestValueToInterface_Message(t *testing.T) {
	t.Parallel()

	msg := wrapperspb.String("test")
	value := protoreflect.ValueOfMessage(msg.ProtoReflect())

	result := valueToInterface(value)

	assert.NotNil(t, result)
}

func TestValueToInterface_List(t *testing.T) {
	t.Parallel()

	msg := &fieldmaskpb.FieldMask{Paths: []string{"a", "b", "c"}}
	fd := msg.ProtoReflect().Descriptor().Fields().ByName("paths")
	value := msg.ProtoReflect().Get(fd)

	result := valueToInterface(value)

	assert.NotNil(t, result)
	resultSlice, ok := result.([]interface{})
	require.True(t, ok)
	assert.Len(t, resultSlice, 3)
}

func TestValueToInterface_Map(t *testing.T) {
	t.Parallel()

	msg, err := structpb.NewStruct(map[string]interface{}{
		"key1": "value1",
		"key2": "value2",
	})
	require.NoError(t, err)

	fd := msg.ProtoReflect().Descriptor().Fields().ByName("fields")
	value := msg.ProtoReflect().Get(fd)

	result := valueToInterface(value)

	assert.NotNil(t, result)
	resultMap, ok := result.(map[string]interface{})
	require.True(t, ok)
	assert.Len(t, resultMap, 2)
}
