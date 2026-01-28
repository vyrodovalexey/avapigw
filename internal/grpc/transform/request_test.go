// Package transform provides gRPC-specific data transformation capabilities.
package transform

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestNewGRPCRequestTransformer(t *testing.T) {
	tests := []struct {
		name   string
		logger observability.Logger
		opts   []GRPCRequestTransformerOption
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
			opts: []GRPCRequestTransformerOption{
				WithRequestMsgTransformer(NewProtobufTransformer(nil)),
			},
		},
		{
			name:   "with custom metadata transformer",
			logger: observability.NopLogger(),
			opts: []GRPCRequestTransformerOption{
				WithRequestMetaTransformer(NewMetadataTransformer(nil)),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transformer := NewGRPCRequestTransformer(tt.logger, tt.opts...)
			assert.NotNil(t, transformer)
		})
	}
}

func TestGRPCRequestTransformer_TransformRequest(t *testing.T) {
	transformer := NewGRPCRequestTransformer(observability.NopLogger())
	ctx := context.Background()

	tests := []struct {
		name     string
		msg      *fieldmaskpb.FieldMask
		md       metadata.MD
		cfg      *config.GRPCRequestTransformConfig
		checkMsg func(t *testing.T, msg *fieldmaskpb.FieldMask)
		checkMD  func(t *testing.T, md metadata.MD)
		wantErr  bool
	}{
		{
			name: "nil config returns original",
			msg:  &fieldmaskpb.FieldMask{Paths: []string{"test"}},
			md:   metadata.Pairs("key", "value"),
			cfg:  nil,
			checkMsg: func(t *testing.T, msg *fieldmaskpb.FieldMask) {
				assert.Equal(t, []string{"test"}, msg.Paths)
			},
			checkMD: func(t *testing.T, md metadata.MD) {
				assert.Equal(t, "value", md.Get("key")[0])
			},
		},
		{
			name: "inject static metadata",
			msg:  &fieldmaskpb.FieldMask{Paths: []string{"test"}},
			md:   metadata.Pairs("existing", "value"),
			cfg: &config.GRPCRequestTransformConfig{
				StaticMetadata: map[string]string{
					"x-custom": "custom-value",
				},
			},
			checkMD: func(t *testing.T, md metadata.MD) {
				assert.Equal(t, "value", md.Get("existing")[0])
				assert.Equal(t, "custom-value", md.Get("x-custom")[0])
			},
		},
		{
			name: "override authority",
			msg:  &fieldmaskpb.FieldMask{Paths: []string{"test"}},
			md:   metadata.MD{},
			cfg: &config.GRPCRequestTransformConfig{
				AuthorityOverride: "custom-authority",
			},
			checkMD: func(t *testing.T, md metadata.MD) {
				assert.Equal(t, "custom-authority", md.Get(":authority")[0])
			},
		},
		{
			name: "nil message",
			msg:  nil,
			md:   metadata.MD{},
			cfg:  &config.GRPCRequestTransformConfig{},
			checkMsg: func(t *testing.T, msg *fieldmaskpb.FieldMask) {
				assert.Nil(t, msg)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resultMsg, resultMD, err := transformer.TransformRequest(ctx, tt.msg, tt.md, tt.cfg)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)

				if tt.checkMsg != nil {
					if resultMsg != nil {
						resultMask, ok := resultMsg.(*fieldmaskpb.FieldMask)
						require.True(t, ok)
						tt.checkMsg(t, resultMask)
					} else {
						tt.checkMsg(t, nil)
					}
				}

				if tt.checkMD != nil {
					tt.checkMD(t, resultMD)
				}
			}
		})
	}
}

func TestGRPCRequestTransformer_InjectDeadline(t *testing.T) {
	transformer := NewGRPCRequestTransformer(observability.NopLogger())

	tests := []struct {
		name     string
		deadline time.Duration
		hasCtx   bool
	}{
		{
			name:     "positive deadline",
			deadline: 5 * time.Second,
			hasCtx:   true,
		},
		{
			name:     "zero deadline",
			deadline: 0,
			hasCtx:   false,
		},
		{
			name:     "negative deadline",
			deadline: -1 * time.Second,
			hasCtx:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			newCtx, cancel := transformer.InjectDeadline(ctx, tt.deadline)
			defer cancel()

			if tt.hasCtx && tt.deadline > 0 {
				deadline, ok := newCtx.Deadline()
				assert.True(t, ok)
				assert.True(t, deadline.After(time.Now()))
			}
		})
	}
}

func TestGRPCRequestTransformer_OverrideAuthority(t *testing.T) {
	transformer := NewGRPCRequestTransformer(observability.NopLogger())

	tests := []struct {
		name      string
		md        metadata.MD
		authority string
		check     func(t *testing.T, result metadata.MD)
	}{
		{
			name:      "override authority",
			md:        metadata.Pairs("key", "value"),
			authority: "custom-authority",
			check: func(t *testing.T, result metadata.MD) {
				assert.Equal(t, "custom-authority", result.Get(":authority")[0])
				assert.Equal(t, "value", result.Get("key")[0])
			},
		},
		{
			name:      "empty authority",
			md:        metadata.Pairs("key", "value"),
			authority: "",
			check: func(t *testing.T, result metadata.MD) {
				assert.Empty(t, result.Get(":authority"))
			},
		},
		{
			name:      "nil metadata",
			md:        nil,
			authority: "custom-authority",
			check: func(t *testing.T, result metadata.MD) {
				assert.Equal(t, "custom-authority", result.Get(":authority")[0])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := transformer.OverrideAuthority(tt.md, tt.authority)
			tt.check(t, result)
		})
	}
}

func TestGRPCRequestTransformer_ValidateRequest(t *testing.T) {
	transformer := NewGRPCRequestTransformer(observability.NopLogger())
	ctx := context.Background()

	tests := []struct {
		name    string
		msg     *fieldmaskpb.FieldMask
		wantErr bool
	}{
		{
			name:    "valid message",
			msg:     &fieldmaskpb.FieldMask{Paths: []string{"test"}},
			wantErr: false,
		},
		{
			name:    "nil message",
			msg:     nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := transformer.ValidateRequest(ctx, tt.msg)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestGRPCRequestTransformer_TransformRequestWithDeadline(t *testing.T) {
	transformer := NewGRPCRequestTransformer(observability.NopLogger())
	ctx := context.Background()

	tests := []struct {
		name        string
		msg         *fieldmaskpb.FieldMask
		md          metadata.MD
		cfg         *config.GRPCRequestTransformConfig
		wantErr     bool
		hasDeadline bool
	}{
		{
			name: "with deadline",
			msg:  &fieldmaskpb.FieldMask{Paths: []string{"test"}},
			md:   metadata.MD{},
			cfg: &config.GRPCRequestTransformConfig{
				InjectDeadline: config.Duration(5 * time.Second),
			},
			hasDeadline: true,
		},
		{
			name: "without deadline",
			msg:  &fieldmaskpb.FieldMask{Paths: []string{"test"}},
			md:   metadata.MD{},
			cfg:  &config.GRPCRequestTransformConfig{},
		},
		{
			name: "nil config",
			msg:  &fieldmaskpb.FieldMask{Paths: []string{"test"}},
			md:   metadata.MD{},
			cfg:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resultCtx, resultMsg, resultMD, cancel, err := transformer.TransformRequestWithDeadline(ctx, tt.msg, tt.md, tt.cfg)
			defer cancel()

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, resultMsg)
				assert.NotNil(t, resultMD)

				if tt.hasDeadline {
					_, ok := resultCtx.Deadline()
					assert.True(t, ok)
				}
			}
		})
	}
}

func TestWithRequestMsgTransformer(t *testing.T) {
	customTransformer := NewProtobufTransformer(observability.NopLogger())
	opt := WithRequestMsgTransformer(customTransformer)

	rt := &GRPCRequestTransformer{}
	opt(rt)

	assert.Equal(t, customTransformer, rt.msgTransformer)
}

func TestWithRequestMetaTransformer(t *testing.T) {
	customTransformer := NewMetadataTransformer(observability.NopLogger())
	opt := WithRequestMetaTransformer(customTransformer)

	rt := &GRPCRequestTransformer{}
	opt(rt)

	assert.Equal(t, customTransformer, rt.metaTransformer)
}

func TestGRPCRequestTransformer_TransformRequest_WithValidation(t *testing.T) {
	transformer := NewGRPCRequestTransformer(observability.NopLogger())
	ctx := context.Background()

	tests := []struct {
		name    string
		msg     *fieldmaskpb.FieldMask
		cfg     *config.GRPCRequestTransformConfig
		wantErr bool
	}{
		{
			name: "validation passes",
			msg:  &fieldmaskpb.FieldMask{Paths: []string{"test"}},
			cfg: &config.GRPCRequestTransformConfig{
				ValidateBeforeTransform: true,
			},
			wantErr: false,
		},
		{
			name: "validation fails - nil message",
			msg:  nil,
			cfg: &config.GRPCRequestTransformConfig{
				ValidateBeforeTransform: true,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := transformer.TransformRequest(ctx, tt.msg, metadata.MD{}, tt.cfg)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
