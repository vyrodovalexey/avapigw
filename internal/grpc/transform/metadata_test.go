// Package transform provides gRPC-specific data transformation capabilities.
package transform

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestNewMetadataTransformer(t *testing.T) {
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
			transformer := NewMetadataTransformer(tt.logger)
			assert.NotNil(t, transformer)
		})
	}
}

func TestMetadataTransformer_TransformMetadata(t *testing.T) {
	transformer := NewMetadataTransformer(observability.NopLogger())
	ctx := context.Background()

	tests := []struct {
		name    string
		md      metadata.MD
		cfg     *config.GRPCRequestTransformConfig
		check   func(t *testing.T, result metadata.MD)
		wantErr bool
	}{
		{
			name: "nil config returns original",
			md:   metadata.Pairs("key", "value"),
			cfg:  nil,
			check: func(t *testing.T, result metadata.MD) {
				assert.Equal(t, "value", result.Get("key")[0])
			},
		},
		{
			name: "inject static metadata",
			md:   metadata.Pairs("existing", "value"),
			cfg: &config.GRPCRequestTransformConfig{
				StaticMetadata: map[string]string{
					"x-custom-header": "custom-value",
				},
			},
			check: func(t *testing.T, result metadata.MD) {
				assert.Equal(t, "value", result.Get("existing")[0])
				assert.Equal(t, "custom-value", result.Get("x-custom-header")[0])
			},
		},
		{
			name: "empty config",
			md:   metadata.Pairs("key", "value"),
			cfg:  &config.GRPCRequestTransformConfig{},
			check: func(t *testing.T, result metadata.MD) {
				assert.Equal(t, "value", result.Get("key")[0])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := transformer.TransformMetadata(ctx, tt.md, tt.cfg)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				if tt.check != nil {
					tt.check(t, result)
				}
			}
		})
	}
}

func TestMetadataTransformer_TransformTrailerMetadata(t *testing.T) {
	transformer := NewMetadataTransformer(observability.NopLogger())
	ctx := context.Background()

	tests := []struct {
		name    string
		md      metadata.MD
		cfg     *config.GRPCResponseTransformConfig
		check   func(t *testing.T, result metadata.MD)
		wantErr bool
	}{
		{
			name: "nil config returns original",
			md:   metadata.Pairs("key", "value"),
			cfg:  nil,
			check: func(t *testing.T, result metadata.MD) {
				assert.Equal(t, "value", result.Get("key")[0])
			},
		},
		{
			name: "inject trailer metadata",
			md:   metadata.Pairs("existing", "value"),
			cfg: &config.GRPCResponseTransformConfig{
				TrailerMetadata: map[string]string{
					"x-trailer": "trailer-value",
				},
			},
			check: func(t *testing.T, result metadata.MD) {
				assert.Equal(t, "value", result.Get("existing")[0])
				assert.Equal(t, "trailer-value", result.Get("x-trailer")[0])
			},
		},
		{
			name: "empty trailer metadata",
			md:   metadata.Pairs("key", "value"),
			cfg: &config.GRPCResponseTransformConfig{
				TrailerMetadata: map[string]string{},
			},
			check: func(t *testing.T, result metadata.MD) {
				assert.Equal(t, "value", result.Get("key")[0])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := transformer.TransformTrailerMetadata(ctx, tt.md, tt.cfg)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				if tt.check != nil {
					tt.check(t, result)
				}
			}
		})
	}
}

func TestMetadataTransformer_InjectStaticMetadata(t *testing.T) {
	transformer := NewMetadataTransformer(observability.NopLogger())

	tests := []struct {
		name   string
		md     metadata.MD
		static map[string]string
		check  func(t *testing.T, result metadata.MD)
	}{
		{
			name:   "inject into existing metadata",
			md:     metadata.Pairs("existing", "value"),
			static: map[string]string{"new-key": "new-value"},
			check: func(t *testing.T, result metadata.MD) {
				assert.Equal(t, "value", result.Get("existing")[0])
				assert.Equal(t, "new-value", result.Get("new-key")[0])
			},
		},
		{
			name:   "inject into nil metadata",
			md:     nil,
			static: map[string]string{"key": "value"},
			check: func(t *testing.T, result metadata.MD) {
				assert.Equal(t, "value", result.Get("key")[0])
			},
		},
		{
			name:   "inject multiple values",
			md:     metadata.MD{},
			static: map[string]string{"key1": "value1", "key2": "value2"},
			check: func(t *testing.T, result metadata.MD) {
				assert.Equal(t, "value1", result.Get("key1")[0])
				assert.Equal(t, "value2", result.Get("key2")[0])
			},
		},
		{
			name:   "override existing key",
			md:     metadata.Pairs("key", "old-value"),
			static: map[string]string{"key": "new-value"},
			check: func(t *testing.T, result metadata.MD) {
				assert.Equal(t, "new-value", result.Get("key")[0])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := transformer.InjectStaticMetadata(tt.md, tt.static)
			tt.check(t, result)
		})
	}
}

func TestMetadataTransformer_InjectDynamicMetadata(t *testing.T) {
	transformer := NewMetadataTransformer(observability.NopLogger())
	ctx := context.Background()

	tests := []struct {
		name    string
		md      metadata.MD
		dynamic []config.DynamicMetadata
		tctx    *TransformContext
		check   func(t *testing.T, result metadata.MD)
		wantErr bool
	}{
		{
			name: "inject from JWT claims",
			md:   metadata.MD{},
			dynamic: []config.DynamicMetadata{
				{Key: "x-user-id", Source: "jwt.claim.sub"},
			},
			tctx: func() *TransformContext {
				tc := NewTransformContext(nil)
				tc.Claims = map[string]interface{}{"sub": "user123"}
				return tc
			}(),
			check: func(t *testing.T, result metadata.MD) {
				assert.Equal(t, "user123", result.Get("x-user-id")[0])
			},
		},
		{
			name: "inject from peer address",
			md:   metadata.MD{},
			dynamic: []config.DynamicMetadata{
				{Key: "x-peer-address", Source: "peer.address"},
			},
			tctx: func() *TransformContext {
				tc := NewTransformContext(nil)
				tc.PeerAddress = "192.168.1.1:8080"
				return tc
			}(),
			check: func(t *testing.T, result metadata.MD) {
				assert.Equal(t, "192.168.1.1:8080", result.Get("x-peer-address")[0])
			},
		},
		{
			name: "inject from request header",
			md:   metadata.MD{},
			dynamic: []config.DynamicMetadata{
				{Key: "x-forwarded", Source: "request.header.authorization"},
			},
			tctx: func() *TransformContext {
				tc := NewTransformContext(nil)
				tc.IncomingMetadata = metadata.Pairs("authorization", "Bearer token123")
				return tc
			}(),
			check: func(t *testing.T, result metadata.MD) {
				assert.Equal(t, "Bearer token123", result.Get("x-forwarded")[0])
			},
		},
		{
			name: "inject from context values",
			md:   metadata.MD{},
			dynamic: []config.DynamicMetadata{
				{Key: "x-request-id", Source: "context.request_id"},
				{Key: "x-trace-id", Source: "context.trace_id"},
			},
			tctx: func() *TransformContext {
				tc := NewTransformContext(nil)
				tc.RequestID = "req-123"
				tc.TraceID = "trace-456"
				return tc
			}(),
			check: func(t *testing.T, result metadata.MD) {
				assert.Equal(t, "req-123", result.Get("x-request-id")[0])
				assert.Equal(t, "trace-456", result.Get("x-trace-id")[0])
			},
		},
		{
			name: "skip empty key",
			md:   metadata.MD{},
			dynamic: []config.DynamicMetadata{
				{Key: "", Source: "jwt.claim.sub"},
			},
			tctx: NewTransformContext(nil),
			check: func(t *testing.T, result metadata.MD) {
				assert.Empty(t, result)
			},
		},
		{
			name: "skip empty source",
			md:   metadata.MD{},
			dynamic: []config.DynamicMetadata{
				{Key: "x-header", Source: ""},
			},
			tctx: NewTransformContext(nil),
			check: func(t *testing.T, result metadata.MD) {
				assert.Empty(t, result)
			},
		},
		{
			name:    "nil metadata creates new",
			md:      nil,
			dynamic: []config.DynamicMetadata{},
			tctx:    NewTransformContext(nil),
			check: func(t *testing.T, result metadata.MD) {
				assert.NotNil(t, result)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := transformer.InjectDynamicMetadata(ctx, tt.md, tt.dynamic, tt.tctx)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				if tt.check != nil {
					tt.check(t, result)
				}
			}
		})
	}
}

func TestMetadataTransformer_ExtractValue(t *testing.T) {
	transformer := NewMetadataTransformer(observability.NopLogger())
	ctx := context.Background()

	tests := []struct {
		name    string
		source  string
		tctx    *TransformContext
		want    string
		wantErr bool
	}{
		{
			name:   "extract JWT claim",
			source: "jwt.claim.sub",
			tctx: func() *TransformContext {
				tc := NewTransformContext(nil)
				tc.Claims = map[string]interface{}{"sub": "user123"}
				return tc
			}(),
			want: "user123",
		},
		{
			name:   "extract JWT claim direct",
			source: "jwt.sub",
			tctx: func() *TransformContext {
				tc := NewTransformContext(nil)
				tc.Claims = map[string]interface{}{"sub": "user123"}
				return tc
			}(),
			want: "user123",
		},
		{
			name:   "extract peer address",
			source: "peer.address",
			tctx: func() *TransformContext {
				tc := NewTransformContext(nil)
				tc.PeerAddress = "192.168.1.1:8080"
				return tc
			}(),
			want: "192.168.1.1:8080",
		},
		{
			name:   "extract request header",
			source: "request.header.authorization",
			tctx: func() *TransformContext {
				tc := NewTransformContext(nil)
				tc.IncomingMetadata = metadata.Pairs("authorization", "Bearer token")
				return tc
			}(),
			want: "Bearer token",
		},
		{
			name:   "extract context request_id",
			source: "context.request_id",
			tctx: func() *TransformContext {
				tc := NewTransformContext(nil)
				tc.RequestID = "req-123"
				return tc
			}(),
			want: "req-123",
		},
		{
			name:   "extract context trace_id",
			source: "context.trace_id",
			tctx: func() *TransformContext {
				tc := NewTransformContext(nil)
				tc.TraceID = "trace-456"
				return tc
			}(),
			want: "trace-456",
		},
		{
			name:   "extract context span_id",
			source: "context.span_id",
			tctx: func() *TransformContext {
				tc := NewTransformContext(nil)
				tc.SpanID = "span-789"
				return tc
			}(),
			want: "span-789",
		},
		{
			name:   "extract custom data",
			source: "context.custom_key",
			tctx: func() *TransformContext {
				tc := NewTransformContext(nil)
				tc.SetCustomData("custom_key", "custom_value")
				return tc
			}(),
			want: "custom_value",
		},
		{
			name:    "invalid source format",
			source:  "invalid",
			tctx:    NewTransformContext(nil),
			wantErr: true,
		},
		{
			name:    "unknown category",
			source:  "unknown.value",
			tctx:    NewTransformContext(nil),
			wantErr: true,
		},
		{
			name:    "unknown peer property",
			source:  "peer.unknown",
			tctx:    NewTransformContext(nil),
			wantErr: true,
		},
		{
			name:    "unknown request property",
			source:  "request.unknown",
			tctx:    NewTransformContext(nil),
			wantErr: true,
		},
		{
			name:   "missing JWT claim returns empty",
			source: "jwt.claim.missing",
			tctx:   NewTransformContext(nil),
			want:   "",
		},
		{
			name:   "missing header returns empty",
			source: "request.header.missing",
			tctx:   NewTransformContext(nil),
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := transformer.ExtractValue(ctx, tt.source, tt.tctx)

			if tt.wantErr {
				require.Error(t, err)
				assert.ErrorIs(t, err, ErrValueExtraction)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, result)
			}
		})
	}
}

func TestCopyMetadata(t *testing.T) {
	tests := []struct {
		name string
		md   metadata.MD
	}{
		{
			name: "copy metadata",
			md:   metadata.Pairs("key", "value"),
		},
		{
			name: "copy nil metadata",
			md:   nil,
		},
		{
			name: "copy empty metadata",
			md:   metadata.MD{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CopyMetadata(tt.md)

			if tt.md == nil {
				assert.Nil(t, result)
			} else {
				assert.Equal(t, tt.md, result)
				// Ensure it's a copy, not the same reference
				if len(tt.md) > 0 {
					result.Set("new-key", "new-value")
					assert.Empty(t, tt.md.Get("new-key"))
				}
			}
		})
	}
}

func TestMergeMetadata(t *testing.T) {
	tests := []struct {
		name string
		mds  []metadata.MD
		want metadata.MD
	}{
		{
			name: "merge two metadata",
			mds: []metadata.MD{
				metadata.Pairs("key1", "value1"),
				metadata.Pairs("key2", "value2"),
			},
			want: metadata.Pairs("key1", "value1", "key2", "value2"),
		},
		{
			name: "merge with override",
			mds: []metadata.MD{
				metadata.Pairs("key", "value1"),
				metadata.Pairs("key", "value2"),
			},
			want: metadata.Pairs("key", "value2"),
		},
		{
			name: "merge empty",
			mds:  []metadata.MD{},
			want: metadata.MD{},
		},
		{
			name: "merge single",
			mds: []metadata.MD{
				metadata.Pairs("key", "value"),
			},
			want: metadata.Pairs("key", "value"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MergeMetadata(tt.mds...)

			for key, values := range tt.want {
				assert.Equal(t, values, result.Get(key))
			}
		})
	}
}

func TestFilterMetadata(t *testing.T) {
	tests := []struct {
		name      string
		md        metadata.MD
		allowKeys []string
		check     func(t *testing.T, result metadata.MD)
	}{
		{
			name:      "filter to allowed keys",
			md:        metadata.Pairs("key1", "value1", "key2", "value2", "key3", "value3"),
			allowKeys: []string{"key1", "key3"},
			check: func(t *testing.T, result metadata.MD) {
				assert.Equal(t, "value1", result.Get("key1")[0])
				assert.Equal(t, "value3", result.Get("key3")[0])
				assert.Empty(t, result.Get("key2"))
			},
		},
		{
			name:      "nil metadata",
			md:        nil,
			allowKeys: []string{"key"},
			check: func(t *testing.T, result metadata.MD) {
				assert.Nil(t, result)
			},
		},
		{
			name:      "empty allow keys",
			md:        metadata.Pairs("key", "value"),
			allowKeys: []string{},
			check: func(t *testing.T, result metadata.MD) {
				assert.Equal(t, "value", result.Get("key")[0])
			},
		},
		{
			name:      "case insensitive",
			md:        metadata.Pairs("Key", "value"),
			allowKeys: []string{"key"},
			check: func(t *testing.T, result metadata.MD) {
				assert.Equal(t, "value", result.Get("Key")[0])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FilterMetadata(tt.md, tt.allowKeys)
			tt.check(t, result)
		})
	}
}

func TestRemoveMetadataKeys(t *testing.T) {
	tests := []struct {
		name       string
		md         metadata.MD
		removeKeys []string
		check      func(t *testing.T, result metadata.MD)
	}{
		{
			name:       "remove keys",
			md:         metadata.Pairs("key1", "value1", "key2", "value2", "key3", "value3"),
			removeKeys: []string{"key2"},
			check: func(t *testing.T, result metadata.MD) {
				assert.Equal(t, "value1", result.Get("key1")[0])
				assert.Equal(t, "value3", result.Get("key3")[0])
				assert.Empty(t, result.Get("key2"))
			},
		},
		{
			name:       "nil metadata",
			md:         nil,
			removeKeys: []string{"key"},
			check: func(t *testing.T, result metadata.MD) {
				assert.Nil(t, result)
			},
		},
		{
			name:       "empty remove keys",
			md:         metadata.Pairs("key", "value"),
			removeKeys: []string{},
			check: func(t *testing.T, result metadata.MD) {
				assert.Equal(t, "value", result.Get("key")[0])
			},
		},
		{
			name:       "remove non-existent key",
			md:         metadata.Pairs("key", "value"),
			removeKeys: []string{"nonexistent"},
			check: func(t *testing.T, result metadata.MD) {
				assert.Equal(t, "value", result.Get("key")[0])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RemoveMetadataKeys(tt.md, tt.removeKeys)
			tt.check(t, result)
		})
	}
}
