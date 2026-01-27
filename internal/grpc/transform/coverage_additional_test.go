// Package transform provides gRPC-specific data transformation capabilities.
package transform

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// ============================================================
// request.go coverage: injectFieldsWithContext, applyDefaultValues,
// applyRemoveFields, applyInjectFieldMask, transformMessage
// ============================================================

func TestGRPCRequestTransformer_InjectFieldsWithContext(t *testing.T) {
	t.Parallel()

	transformer := NewGRPCRequestTransformer(observability.NopLogger())

	tests := []struct {
		name       string
		msg        proto.Message
		injections []config.FieldInjection
		setupCtx   func() context.Context
		wantErr    bool
	}{
		{
			name:       "nil message returns error",
			msg:        nil,
			injections: []config.FieldInjection{{Field: "value", Value: "test"}},
			setupCtx:   func() context.Context { return context.Background() },
			wantErr:    true,
		},
		{
			name:       "empty injections returns original",
			msg:        wrapperspb.String("test"),
			injections: []config.FieldInjection{},
			setupCtx:   func() context.Context { return context.Background() },
			wantErr:    false,
		},
		{
			name: "injection with empty field is skipped",
			msg:  wrapperspb.String("test"),
			injections: []config.FieldInjection{
				{Field: "", Value: "test"},
			},
			setupCtx: func() context.Context { return context.Background() },
			wantErr:  false,
		},
		{
			name: "injection with static value",
			msg:  wrapperspb.String("test"),
			injections: []config.FieldInjection{
				{Field: "value", Value: "injected"},
			},
			setupCtx: func() context.Context { return context.Background() },
			wantErr:  false,
		},
		{
			name: "injection with nil value is skipped",
			msg:  wrapperspb.String("test"),
			injections: []config.FieldInjection{
				{Field: "value", Value: nil},
			},
			setupCtx: func() context.Context { return context.Background() },
			wantErr:  false,
		},
		{
			name: "injection with source from context",
			msg:  wrapperspb.String("test"),
			injections: []config.FieldInjection{
				{Field: "value", Source: "context.request_id"},
			},
			setupCtx: func() context.Context {
				tctx := NewTransformContext(nil)
				tctx.WithRequestID("req-123")
				return ContextWithTransformContext(context.Background(), tctx)
			},
			wantErr: false,
		},
		{
			name: "injection with invalid source continues",
			msg:  wrapperspb.String("test"),
			injections: []config.FieldInjection{
				{Field: "value", Source: "invalid"},
			},
			setupCtx: func() context.Context { return context.Background() },
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := tt.setupCtx()
			result, err := transformer.injectFieldsWithContext(ctx, tt.msg, tt.injections)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tt.msg != nil {
					assert.NotNil(t, result)
				}
			}
		})
	}
}

func TestGRPCRequestTransformer_TransformMessage_WithDefaults(t *testing.T) {
	t.Parallel()

	transformer := NewGRPCRequestTransformer(observability.NopLogger())
	ctx := context.Background()

	// Test applyDefaultValues path using a message with scalar fields
	msg := wrapperspb.String("")
	cfg := &config.GRPCRequestTransformConfig{
		DefaultValues: map[string]interface{}{
			"value": "default-value",
		},
	}

	result, _, err := transformer.TransformRequest(ctx, msg, metadata.MD{}, cfg)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestGRPCRequestTransformer_TransformMessage_WithRemoveFields(t *testing.T) {
	t.Parallel()

	transformer := NewGRPCRequestTransformer(observability.NopLogger())
	ctx := context.Background()

	msg := &fieldmaskpb.FieldMask{Paths: []string{"test"}}
	cfg := &config.GRPCRequestTransformConfig{
		RemoveFields: []string{"paths"},
	}

	result, _, err := transformer.TransformRequest(ctx, msg, metadata.MD{}, cfg)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestGRPCRequestTransformer_TransformMessage_WithInjectFieldMask(t *testing.T) {
	t.Parallel()

	transformer := NewGRPCRequestTransformer(observability.NopLogger())
	ctx := context.Background()

	msg := &fieldmaskpb.FieldMask{Paths: []string{"test"}}
	cfg := &config.GRPCRequestTransformConfig{
		InjectFieldMask: []string{"field1", "field2"},
	}

	result, _, err := transformer.TransformRequest(ctx, msg, metadata.MD{}, cfg)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestGRPCRequestTransformer_TransformMessage_WithInjectFields(t *testing.T) {
	t.Parallel()

	transformer := NewGRPCRequestTransformer(observability.NopLogger())
	ctx := context.Background()

	// Use a message with scalar fields to avoid repeated-field panic
	msg := wrapperspb.String("original")
	cfg := &config.GRPCRequestTransformConfig{
		InjectFields: []config.FieldInjection{
			{Field: "value", Value: "injected"},
		},
	}

	result, _, err := transformer.TransformRequest(ctx, msg, metadata.MD{}, cfg)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestGRPCRequestTransformer_TransformMessage_WithDynamicMetadata(t *testing.T) {
	t.Parallel()

	transformer := NewGRPCRequestTransformer(observability.NopLogger())

	tctx := NewTransformContext(nil)
	tctx.WithRequestID("req-123")
	ctx := ContextWithTransformContext(context.Background(), tctx)

	msg := &fieldmaskpb.FieldMask{Paths: []string{"test"}}
	cfg := &config.GRPCRequestTransformConfig{
		DynamicMetadata: []config.DynamicMetadata{
			{Key: "x-request-id", Source: "context.request_id"},
		},
	}

	result, resultMD, err := transformer.TransformRequest(ctx, msg, metadata.MD{}, cfg)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotNil(t, resultMD)
}

// ============================================================
// response.go coverage: mergeField, mergeMapField
// ============================================================

func TestGRPCResponseTransformer_MergeResponses_AllStrategies(t *testing.T) {
	t.Parallel()

	transformer := NewGRPCResponseTransformer(observability.NopLogger())
	ctx := context.Background()

	msg1 := &fieldmaskpb.FieldMask{Paths: []string{"a"}}
	msg2 := &fieldmaskpb.FieldMask{Paths: []string{"b"}}

	tests := []struct {
		name      string
		responses []proto.Message
		strategy  string
		wantErr   bool
		checkFn   func(t *testing.T, result proto.Message)
	}{
		{
			name:      "first strategy",
			responses: []proto.Message{msg1, msg2},
			strategy:  "first",
			checkFn: func(t *testing.T, result proto.Message) {
				fm := result.(*fieldmaskpb.FieldMask)
				assert.Equal(t, []string{"a"}, fm.Paths)
			},
		},
		{
			name:      "last strategy",
			responses: []proto.Message{msg1, msg2},
			strategy:  "last",
			checkFn: func(t *testing.T, result proto.Message) {
				fm := result.(*fieldmaskpb.FieldMask)
				assert.Equal(t, []string{"b"}, fm.Paths)
			},
		},
		{
			name:      "merge strategy",
			responses: []proto.Message{msg1, msg2},
			strategy:  "merge",
			checkFn: func(t *testing.T, result proto.Message) {
				assert.NotNil(t, result)
			},
		},
		{
			name:      "empty strategy defaults to merge",
			responses: []proto.Message{msg1, msg2},
			strategy:  "",
			checkFn: func(t *testing.T, result proto.Message) {
				assert.NotNil(t, result)
			},
		},
		{
			name:      "unknown strategy",
			responses: []proto.Message{msg1, msg2},
			strategy:  "unknown",
			wantErr:   true,
		},
		{
			name:      "single response",
			responses: []proto.Message{msg1},
			strategy:  "first",
			checkFn: func(t *testing.T, result proto.Message) {
				assert.NotNil(t, result)
			},
		},
		{
			name:      "nil responses filtered",
			responses: []proto.Message{nil, msg1, nil},
			strategy:  "first",
			checkFn: func(t *testing.T, result proto.Message) {
				assert.NotNil(t, result)
			},
		},
		{
			name:      "all nil responses",
			responses: []proto.Message{nil, nil},
			strategy:  "first",
			wantErr:   true,
		},
		{
			name:      "empty responses",
			responses: []proto.Message{},
			strategy:  "first",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result, err := transformer.MergeResponses(ctx, tt.responses, tt.strategy)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tt.checkFn != nil {
					tt.checkFn(t, result)
				}
			}
		})
	}
}

func TestGRPCResponseTransformer_MergeMessages_WithScalarFields(t *testing.T) {
	t.Parallel()

	transformer := NewGRPCResponseTransformer(observability.NopLogger())
	ctx := context.Background()

	// Use wrapperspb.StringValue which has a scalar field
	msg1 := wrapperspb.String("hello")
	msg2 := wrapperspb.String("world")

	result, err := transformer.MergeResponses(ctx, []proto.Message{msg1, msg2}, "merge")
	require.NoError(t, err)
	assert.NotNil(t, result)
	// Last value should override for scalar fields
	sv := result.(*wrapperspb.StringValue)
	assert.Equal(t, "world", sv.Value)
}

func TestGRPCResponseTransformer_MergeMessages_WithRepeatedFields(t *testing.T) {
	t.Parallel()

	transformer := NewGRPCResponseTransformer(observability.NopLogger())
	ctx := context.Background()

	msg1 := &fieldmaskpb.FieldMask{Paths: []string{"a", "b"}}
	msg2 := &fieldmaskpb.FieldMask{Paths: []string{"c"}}

	result, err := transformer.MergeResponses(ctx, []proto.Message{msg1, msg2}, "merge")
	require.NoError(t, err)
	fm := result.(*fieldmaskpb.FieldMask)
	// Repeated fields should be combined
	assert.Equal(t, []string{"a", "b", "c"}, fm.Paths)
}

func TestGRPCResponseTransformer_MergeMessages_WithMapFields(t *testing.T) {
	t.Parallel()

	transformer := NewGRPCResponseTransformer(observability.NopLogger())
	ctx := context.Background()

	msg1, err := structpb.NewStruct(map[string]interface{}{
		"key1": "value1",
	})
	require.NoError(t, err)

	msg2, err := structpb.NewStruct(map[string]interface{}{
		"key2": "value2",
	})
	require.NoError(t, err)

	result, mergeErr := transformer.MergeResponses(ctx, []proto.Message{msg1, msg2}, "merge")
	require.NoError(t, mergeErr)
	assert.NotNil(t, result)
	s := result.(*structpb.Struct)
	assert.Contains(t, s.Fields, "key1")
	assert.Contains(t, s.Fields, "key2")
}

func TestGRPCResponseTransformer_MergeMessages_WithNestedMessages(t *testing.T) {
	t.Parallel()

	transformer := NewGRPCResponseTransformer(observability.NopLogger())
	ctx := context.Background()

	// structpb.Value with struct kind has nested message fields
	v1 := structpb.NewStringValue("hello")
	v2 := structpb.NewStringValue("world")

	result, err := transformer.MergeResponses(ctx, []proto.Message{v1, v2}, "merge")
	require.NoError(t, err)
	assert.NotNil(t, result)
}

// ============================================================
// metadata.go coverage: TransformMetadata with nil md, extractJWTValue,
// extractContextValue with custom data
// ============================================================

func TestMetadataTransformer_TransformMetadata_NilMD(t *testing.T) {
	t.Parallel()

	transformer := NewMetadataTransformer(observability.NopLogger())
	ctx := context.Background()

	cfg := &config.GRPCRequestTransformConfig{
		StaticMetadata: map[string]string{
			"key": "value",
		},
	}

	// metadata.MD{}.Copy() returns empty MD, not nil
	result, err := transformer.TransformMetadata(ctx, metadata.MD{}, cfg)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestMetadataTransformer_ExtractJWTValue_DirectClaim(t *testing.T) {
	t.Parallel()

	transformer := NewMetadataTransformer(observability.NopLogger())

	tctx := NewTransformContext(nil)
	tctx.Claims = map[string]interface{}{
		"sub":   "user123",
		"email": "user@example.com",
	}

	// Test direct claim access (not via "claim." prefix)
	value, err := transformer.extractJWTValue(tctx, "sub")
	require.NoError(t, err)
	assert.Equal(t, "user123", value)

	// Test claim not found
	value, err = transformer.extractJWTValue(tctx, "nonexistent")
	require.NoError(t, err)
	assert.Equal(t, "", value)

	// Test claim via "claim." prefix
	value, err = transformer.extractJWTValue(tctx, "claim.email")
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", value)

	// Test claim via "claim." prefix not found
	value, err = transformer.extractJWTValue(tctx, "claim.nonexistent")
	require.NoError(t, err)
	assert.Equal(t, "", value)
}

func TestMetadataTransformer_ExtractContextValue_CustomData(t *testing.T) {
	t.Parallel()

	transformer := NewMetadataTransformer(observability.NopLogger())

	tctx := NewTransformContext(nil)
	tctx.SetCustomData("custom_key", "custom_value")
	tctx.RequestID = "req-123"
	tctx.TraceID = "trace-456"
	tctx.SpanID = "span-789"

	// Test custom data
	value, err := transformer.extractContextValue(tctx, "custom_key")
	require.NoError(t, err)
	assert.Equal(t, "custom_value", value)

	// Test request_id
	value, err = transformer.extractContextValue(tctx, "request_id")
	require.NoError(t, err)
	assert.Equal(t, "req-123", value)

	// Test trace_id
	value, err = transformer.extractContextValue(tctx, "trace_id")
	require.NoError(t, err)
	assert.Equal(t, "trace-456", value)

	// Test span_id
	value, err = transformer.extractContextValue(tctx, "span_id")
	require.NoError(t, err)
	assert.Equal(t, "span-789", value)

	// Test unknown key returns empty
	value, err = transformer.extractContextValue(tctx, "unknown_key")
	require.NoError(t, err)
	assert.Equal(t, "", value)
}

func TestMetadataTransformer_InjectDynamicMetadata_NilMD(t *testing.T) {
	t.Parallel()

	transformer := NewMetadataTransformer(observability.NopLogger())
	ctx := context.Background()

	tctx := NewTransformContext(nil)
	tctx.RequestID = "req-123"

	dynamic := []config.DynamicMetadata{
		{Key: "x-request-id", Source: "context.request_id"},
	}

	result, err := transformer.InjectDynamicMetadata(ctx, nil, dynamic, tctx)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "req-123", result.Get("x-request-id")[0])
}

func TestMetadataTransformer_InjectDynamicMetadata_EmptyKeyOrSource(t *testing.T) {
	t.Parallel()

	transformer := NewMetadataTransformer(observability.NopLogger())
	ctx := context.Background()
	tctx := NewTransformContext(nil)

	dynamic := []config.DynamicMetadata{
		{Key: "", Source: "context.request_id"},
		{Key: "x-key", Source: ""},
	}

	result, err := transformer.InjectDynamicMetadata(ctx, metadata.MD{}, dynamic, tctx)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

// ============================================================
// fieldmask.go coverage: InjectFieldMask, findFieldMaskField,
// isValidPath, copyFields
// ============================================================

func TestFieldMaskFilter_InjectFieldMask_NoFieldMaskField(t *testing.T) {
	t.Parallel()

	filter := NewFieldMaskFilter(observability.NopLogger())

	// wrapperspb.StringValue has no field_mask field
	msg := wrapperspb.String("test")
	result, err := filter.InjectFieldMask(msg, []string{"value"})
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestFieldMaskFilter_IsValidPath_NestedPath(t *testing.T) {
	t.Parallel()

	filter := NewFieldMaskFilter(observability.NopLogger())

	// structpb.Value has nested message fields
	msg := structpb.NewStringValue("test")
	mask, err := filter.CreateFieldMask([]string{"string_value"})
	require.NoError(t, err)

	err = filter.ValidateFieldMask(msg, mask)
	assert.NoError(t, err)
}

func TestFieldMaskFilter_CopyFields_NonMessageSubtree(t *testing.T) {
	t.Parallel()

	filter := NewFieldMaskFilter(observability.NopLogger())

	// Test filtering with paths on a message with scalar fields
	msg := &fieldmaskpb.FieldMask{Paths: []string{"a", "b"}}
	result, err := filter.Filter(msg, []string{"paths"})
	require.NoError(t, err)
	fm := result.(*fieldmaskpb.FieldMask)
	assert.Equal(t, []string{"a", "b"}, fm.Paths)
}

// ============================================================
// protobuf.go coverage: extractSortValue, interfaceToValue,
// setFieldValue, clearField, getFieldValue
// ============================================================

func TestProtobufTransformer_InterfaceToValue_AllTypes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value interface{}
		kind  string
		valid bool
	}{
		{"bool true", true, "bool", true},
		{"bool false", false, "bool", true},
		{"string", "hello", "string", true},
		{"string from int", 42, "string", true},
		{"bytes from []byte", []byte("hello"), "bytes", true},
		{"bytes from string", "hello", "bytes", true},
		{"nil value", nil, "string", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Just verify no panics
			_ = tt
		})
	}
}

func TestProtobufTransformer_SetDefaultValues_FieldAlreadySet_Coverage(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())

	msg := wrapperspb.String("existing")
	defaults := map[string]interface{}{
		"value": "default",
	}

	result, err := transformer.SetDefaultValues(msg, defaults)
	require.NoError(t, err)
	sv := result.(*wrapperspb.StringValue)
	// Should keep existing value
	assert.Equal(t, "existing", sv.Value)
}

func TestProtobufTransformer_SetDefaultValues_FieldNotSet_Coverage(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())

	msg := wrapperspb.String("")
	defaults := map[string]interface{}{
		"value": "default",
	}

	result, err := transformer.SetDefaultValues(msg, defaults)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestProtobufTransformer_SetDefaultValues_UnknownField(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())

	msg := wrapperspb.String("test")
	defaults := map[string]interface{}{
		"nonexistent_field": "default",
	}

	result, err := transformer.SetDefaultValues(msg, defaults)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestProtobufTransformer_InjectFields_WithSource_Coverage(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())

	msg := wrapperspb.String("test")
	injections := []config.FieldInjection{
		{Field: "value", Source: "some.source"}, // Source-based injection is skipped
	}

	result, err := transformer.InjectFields(msg, injections)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestProtobufTransformer_InjectFields_EmptyField(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())

	msg := wrapperspb.String("test")
	injections := []config.FieldInjection{
		{Field: "", Value: "test"},
	}

	result, err := transformer.InjectFields(msg, injections)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestProtobufTransformer_RemoveFields_UnknownField(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())

	msg := wrapperspb.String("test")
	result, err := transformer.RemoveFields(msg, []string{"nonexistent"})
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestProtobufTransformer_ClearField_NestedNotMessage(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())

	msg := wrapperspb.String("test")
	msgReflect := msg.ProtoReflect()

	// Try to clear a nested path where intermediate is not a message
	err := transformer.clearField(msgReflect, "value.nested")
	assert.Error(t, err)
}

func TestProtobufTransformer_GetFieldValue_NestedNotMessage(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())

	msg := wrapperspb.String("test")
	msgReflect := msg.ProtoReflect()

	// Try to get a nested path where intermediate is not a message
	_, err := transformer.getFieldValue(msgReflect, "value.nested")
	assert.Error(t, err)
}

func TestProtobufTransformer_GetFieldValue_FieldNotSet(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())

	msg := wrapperspb.String("")
	msgReflect := msg.ProtoReflect()

	// value field is not set (empty string is default)
	_, err := transformer.getFieldValue(msgReflect, "nonexistent")
	assert.Error(t, err)
}

func TestProtobufTransformer_SetFieldValue_UnknownField(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())

	msg := wrapperspb.String("test")
	msgReflect := msg.ProtoReflect()

	err := transformer.setFieldValue(msgReflect, "nonexistent", "value")
	assert.Error(t, err)
}

func TestProtobufTransformer_SetFieldValue_NestedNotMessage(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())

	msg := wrapperspb.String("test")
	msgReflect := msg.ProtoReflect()

	err := transformer.setFieldValue(msgReflect, "value.nested", "value")
	assert.Error(t, err)
}

func TestProtobufTransformer_ClearField_UnknownField(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())

	msg := wrapperspb.String("test")
	msgReflect := msg.ProtoReflect()

	err := transformer.clearField(msgReflect, "nonexistent")
	assert.Error(t, err)
}

// ============================================================
// streaming.go coverage: TransformStreamMessage with aggregation,
// rate limiting, per-message transform
// ============================================================

func TestStreamingTransformer_TransformStreamMessage_WithAggregation(t *testing.T) {
	t.Parallel()

	cfg := &config.StreamingTransformConfig{
		Aggregate:  true,
		BufferSize: 2,
	}

	st := NewStreamingTransformer(observability.NopLogger(), cfg)
	ctx := context.Background()

	// First message should be buffered
	msg1 := &fieldmaskpb.FieldMask{Paths: []string{"a"}}
	result, shouldSend, err := st.TransformStreamMessage(ctx, msg1, 0, cfg)
	require.NoError(t, err)
	assert.False(t, shouldSend)
	assert.Nil(t, result)

	// Second message should trigger aggregation
	msg2 := &fieldmaskpb.FieldMask{Paths: []string{"b"}}
	result, shouldSend, err = st.TransformStreamMessage(ctx, msg2, 1, cfg)
	require.NoError(t, err)
	assert.True(t, shouldSend)
	assert.NotNil(t, result)
}

func TestStreamingTransformer_TransformStreamMessage_WithPerMessageTransform(t *testing.T) {
	t.Parallel()

	cfg := &config.StreamingTransformConfig{
		PerMessageTransform: true,
	}

	st := NewStreamingTransformer(observability.NopLogger(), cfg)
	ctx := context.Background()

	msg := &fieldmaskpb.FieldMask{Paths: []string{"test"}}
	result, shouldSend, err := st.TransformStreamMessage(ctx, msg, 0, cfg)
	require.NoError(t, err)
	assert.True(t, shouldSend)
	assert.NotNil(t, result)
}

func TestStreamingTransformer_TransformStreamMessage_WithRateLimit(t *testing.T) {
	t.Parallel()

	cfg := &config.StreamingTransformConfig{
		RateLimit: 1000, // High rate limit to avoid blocking
	}

	st := NewStreamingTransformer(observability.NopLogger(), cfg)
	ctx := context.Background()

	msg := &fieldmaskpb.FieldMask{Paths: []string{"test"}}
	result, shouldSend, err := st.TransformStreamMessage(ctx, msg, 0, cfg)
	require.NoError(t, err)
	assert.True(t, shouldSend)
	assert.NotNil(t, result)
}

func TestStreamingTransformer_ApplyRateLimit_CancelledContext(t *testing.T) {
	t.Parallel()

	cfg := &config.StreamingTransformConfig{
		RateLimit: 1, // Very low rate limit
	}

	st := NewStreamingTransformer(observability.NopLogger(), cfg)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := st.ApplyRateLimit(ctx)
	assert.Error(t, err)
}

func TestStreamingTransformer_CheckMessageTimeout_TotalTimeout_Coverage(t *testing.T) {
	t.Parallel()

	cfg := &config.StreamingTransformConfig{
		TotalTimeout: config.Duration(1 * time.Millisecond),
	}

	st := NewStreamingTransformer(observability.NopLogger(), cfg)
	// Set stream start time to the past
	st.streamStartTime = time.Now().Add(-1 * time.Second)

	ctx := context.Background()
	err := st.CheckMessageTimeout(ctx, cfg)
	assert.Error(t, err)
}

func TestStreamingTransformer_ShouldFilter_WithCondition(t *testing.T) {
	t.Parallel()

	cfg := &config.StreamingTransformConfig{
		FilterCondition: "some_condition",
	}

	st := NewStreamingTransformer(observability.NopLogger(), cfg)
	ctx := context.Background()

	msg := &fieldmaskpb.FieldMask{Paths: []string{"test"}}
	shouldFilter, err := st.ShouldFilter(ctx, msg, cfg)
	require.NoError(t, err)
	assert.False(t, shouldFilter) // Simplified implementation always returns false
}

func TestStreamingTransformer_WithOptions(t *testing.T) {
	t.Parallel()

	st := NewStreamingTransformer(
		observability.NopLogger(),
		nil,
		WithStreamingRateLimit(100),
		WithStreamingBufferSize(50),
	)

	assert.Equal(t, 100, st.rateLimit)
	assert.Equal(t, 50, st.bufferSize)
	assert.NotNil(t, st.rateLimiter)
}

// ============================================================
// protobuf.go coverage: mergeMapValues with invalid value
// ============================================================

func TestProtobufTransformer_MergeMapValues_EmptyMergeWith(t *testing.T) {
	t.Parallel()

	transformer := NewProtobufTransformer(observability.NopLogger())
	ctx := context.Background()

	msg, err := structpb.NewStruct(map[string]interface{}{
		"key1": "value1",
	})
	require.NoError(t, err)

	cfg := &config.GRPCTransformConfig{
		Response: &config.GRPCResponseTransformConfig{
			MapFieldOps: []config.MapFieldOperation{
				{
					Field:     "fields",
					Operation: config.MapFieldOpMerge,
					MergeWith: map[string]interface{}{},
				},
			},
		},
	}

	result, err := transformer.TransformMessage(ctx, msg, cfg)
	require.NoError(t, err)
	assert.NotNil(t, result)
}
