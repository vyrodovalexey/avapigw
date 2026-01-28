// Package transform provides gRPC-specific data transformation capabilities.
package transform

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// Helper function to convert FieldMask slice to proto.Message slice
func convertFieldMasksToProtoMessages(masks []*fieldmaskpb.FieldMask) []proto.Message {
	result := make([]proto.Message, len(masks))
	for i, m := range masks {
		if m != nil {
			result[i] = m
		} else {
			result[i] = nil
		}
	}
	return result
}

func TestNewGRPCResponseTransformer(t *testing.T) {
	tests := []struct {
		name   string
		logger observability.Logger
		opts   []GRPCResponseTransformerOption
	}{
		{
			name:   "with logger",
			logger: observability.NopLogger(),
		},
		{
			name:   "nil logger",
			logger: nil,
		},
		{
			name:   "with custom message transformer",
			logger: observability.NopLogger(),
			opts: []GRPCResponseTransformerOption{
				WithResponseMsgTransformer(NewProtobufTransformer(nil)),
			},
		},
		{
			name:   "with custom field mask filter",
			logger: observability.NopLogger(),
			opts: []GRPCResponseTransformerOption{
				WithResponseFieldMaskFilter(NewFieldMaskFilter(nil)),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transformer := NewGRPCResponseTransformer(tt.logger, tt.opts...)
			assert.NotNil(t, transformer)
		})
	}
}

func TestGRPCResponseTransformer_TransformResponse(t *testing.T) {
	transformer := NewGRPCResponseTransformer(observability.NopLogger())
	ctx := context.Background()

	// Test nil message separately to avoid typed nil issue
	t.Run("nil message", func(t *testing.T) {
		result, err := transformer.TransformResponse(ctx, nil, &config.GRPCResponseTransformConfig{})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNilMessage)
		assert.Nil(t, result)
	})

	tests := []struct {
		name     string
		msg      *fieldmaskpb.FieldMask
		cfg      *config.GRPCResponseTransformConfig
		checkMsg func(t *testing.T, msg *fieldmaskpb.FieldMask)
		wantErr  bool
		errIs    error
	}{
		{
			name: "nil config returns original",
			msg:  &fieldmaskpb.FieldMask{Paths: []string{"test"}},
			cfg:  nil,
			checkMsg: func(t *testing.T, msg *fieldmaskpb.FieldMask) {
				assert.Equal(t, []string{"test"}, msg.Paths)
			},
		},
		{
			name: "empty config",
			msg:  &fieldmaskpb.FieldMask{Paths: []string{"test"}},
			cfg:  &config.GRPCResponseTransformConfig{},
			checkMsg: func(t *testing.T, msg *fieldmaskpb.FieldMask) {
				assert.Equal(t, []string{"test"}, msg.Paths)
			},
		},
		{
			name: "with field mask",
			msg:  &fieldmaskpb.FieldMask{Paths: []string{"test1", "test2"}},
			cfg: &config.GRPCResponseTransformConfig{
				FieldMask: []string{"paths"},
			},
			checkMsg: func(t *testing.T, msg *fieldmaskpb.FieldMask) {
				assert.NotNil(t, msg)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := transformer.TransformResponse(ctx, tt.msg, tt.cfg)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errIs != nil {
					assert.ErrorIs(t, err, tt.errIs)
				}
			} else {
				require.NoError(t, err)
				if tt.checkMsg != nil {
					resultMask, ok := result.(*fieldmaskpb.FieldMask)
					require.True(t, ok)
					tt.checkMsg(t, resultMask)
				}
			}
		})
	}
}

func TestGRPCResponseTransformer_MergeResponses(t *testing.T) {
	transformer := NewGRPCResponseTransformer(observability.NopLogger())
	ctx := context.Background()

	tests := []struct {
		name      string
		responses []*fieldmaskpb.FieldMask
		strategy  string
		check     func(t *testing.T, result *fieldmaskpb.FieldMask)
		wantErr   bool
	}{
		{
			name:      "empty responses",
			responses: []*fieldmaskpb.FieldMask{},
			strategy:  "first",
			wantErr:   true,
		},
		{
			name: "single response",
			responses: []*fieldmaskpb.FieldMask{
				{Paths: []string{"test"}},
			},
			strategy: "first",
			check: func(t *testing.T, result *fieldmaskpb.FieldMask) {
				assert.Equal(t, []string{"test"}, result.Paths)
			},
		},
		{
			name: "first strategy",
			responses: []*fieldmaskpb.FieldMask{
				{Paths: []string{"first"}},
				{Paths: []string{"second"}},
			},
			strategy: "first",
			check: func(t *testing.T, result *fieldmaskpb.FieldMask) {
				assert.Equal(t, []string{"first"}, result.Paths)
			},
		},
		{
			name: "last strategy",
			responses: []*fieldmaskpb.FieldMask{
				{Paths: []string{"first"}},
				{Paths: []string{"second"}},
			},
			strategy: "last",
			check: func(t *testing.T, result *fieldmaskpb.FieldMask) {
				assert.Equal(t, []string{"second"}, result.Paths)
			},
		},
		{
			name: "merge strategy",
			responses: []*fieldmaskpb.FieldMask{
				{Paths: []string{"first"}},
				{Paths: []string{"second"}},
			},
			strategy: "merge",
			check: func(t *testing.T, result *fieldmaskpb.FieldMask) {
				// Merge combines repeated fields
				assert.Contains(t, result.Paths, "first")
				assert.Contains(t, result.Paths, "second")
			},
		},
		{
			name: "empty strategy defaults to merge",
			responses: []*fieldmaskpb.FieldMask{
				{Paths: []string{"first"}},
				{Paths: []string{"second"}},
			},
			strategy: "",
			check: func(t *testing.T, result *fieldmaskpb.FieldMask) {
				assert.Contains(t, result.Paths, "first")
				assert.Contains(t, result.Paths, "second")
			},
		},
		{
			name: "unknown strategy",
			responses: []*fieldmaskpb.FieldMask{
				{Paths: []string{"first"}},
				{Paths: []string{"second"}},
			},
			strategy: "unknown",
			wantErr:  true,
		},
		{
			name: "filter nil responses",
			responses: []*fieldmaskpb.FieldMask{
				nil,
				{Paths: []string{"valid"}},
				nil,
			},
			strategy: "first",
			check: func(t *testing.T, result *fieldmaskpb.FieldMask) {
				assert.Equal(t, []string{"valid"}, result.Paths)
			},
		},
		{
			name: "all nil responses",
			responses: []*fieldmaskpb.FieldMask{
				nil,
				nil,
			},
			strategy: "first",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Convert to proto.Message slice
			protoResponses := make([]interface{}, len(tt.responses))
			for i, r := range tt.responses {
				if r != nil {
					protoResponses[i] = r
				}
			}

			result, err := transformer.MergeResponses(ctx, convertFieldMasksToProtoMessages(tt.responses), tt.strategy)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				if tt.check != nil {
					resultMask, ok := result.(*fieldmaskpb.FieldMask)
					require.True(t, ok)
					tt.check(t, resultMask)
				}
			}
		})
	}
}

func TestGRPCResponseTransformer_TransformStreamingResponse(t *testing.T) {
	transformer := NewGRPCResponseTransformer(observability.NopLogger())
	ctx := context.Background()

	msg := &fieldmaskpb.FieldMask{Paths: []string{"test"}}
	cfg := &config.GRPCResponseTransformConfig{}

	result, err := transformer.TransformStreamingResponse(ctx, msg, cfg, 0)

	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestGRPCResponseTransformer_FilterResponseFields(t *testing.T) {
	transformer := NewGRPCResponseTransformer(observability.NopLogger())

	// Test nil message separately to avoid typed nil issue
	t.Run("nil message", func(t *testing.T) {
		result, err := transformer.FilterResponseFields(nil, []string{"paths"})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNilMessage)
		assert.Nil(t, result)
	})

	tests := []struct {
		name    string
		msg     *fieldmaskpb.FieldMask
		paths   []string
		wantErr bool
	}{
		{
			name:    "filter fields",
			msg:     &fieldmaskpb.FieldMask{Paths: []string{"test1", "test2"}},
			paths:   []string{"paths"},
			wantErr: false,
		},
		{
			name:    "empty paths",
			msg:     &fieldmaskpb.FieldMask{Paths: []string{"test"}},
			paths:   []string{},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := transformer.FilterResponseFields(tt.msg, tt.paths)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, result)
			}
		})
	}
}

func TestGRPCResponseTransformer_ApplyResponseTransformations(t *testing.T) {
	transformer := NewGRPCResponseTransformer(observability.NopLogger())
	ctx := context.Background()

	msg := &fieldmaskpb.FieldMask{Paths: []string{"test"}}
	cfg := &config.GRPCResponseTransformConfig{}

	result, err := transformer.ApplyResponseTransformations(ctx, msg, cfg)

	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestWithResponseMsgTransformer(t *testing.T) {
	customTransformer := NewProtobufTransformer(observability.NopLogger())
	opt := WithResponseMsgTransformer(customTransformer)

	rt := &GRPCResponseTransformer{}
	opt(rt)

	assert.Equal(t, customTransformer, rt.msgTransformer)
}

func TestWithResponseFieldMaskFilter(t *testing.T) {
	customFilter := NewFieldMaskFilter(observability.NopLogger())
	opt := WithResponseFieldMaskFilter(customFilter)

	rt := &GRPCResponseTransformer{}
	opt(rt)

	assert.Equal(t, customFilter, rt.fieldMaskFilter)
}
