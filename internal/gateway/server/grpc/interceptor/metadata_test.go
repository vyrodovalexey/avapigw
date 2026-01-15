package interceptor

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// TestUnaryMetadataInterceptor tests the unary metadata interceptor
func TestUnaryMetadataInterceptor(t *testing.T) {
	t.Parallel()

	t.Run("passes with nil config", func(t *testing.T) {
		interceptor := UnaryMetadataInterceptor(nil)

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

		resp, err := interceptor(ctx, "request", info, mockUnaryHandler)

		assert.NoError(t, err)
		assert.Equal(t, "response", resp)
	})

	t.Run("adds metadata", func(t *testing.T) {
		config := &MetadataConfig{
			Add: map[string]string{
				"x-added-header": "added-value",
			},
		}

		var capturedMD metadata.MD
		handler := func(ctx context.Context, req interface{}) (interface{}, error) {
			capturedMD, _ = metadata.FromIncomingContext(ctx)
			return "response", nil
		}

		interceptor := UnaryMetadataInterceptor(config)

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

		resp, err := interceptor(ctx, "request", info, handler)

		assert.NoError(t, err)
		assert.Equal(t, "response", resp)
		assert.Contains(t, capturedMD.Get("x-added-header"), "added-value")
	})

	t.Run("sets metadata", func(t *testing.T) {
		config := &MetadataConfig{
			Set: map[string]string{
				"x-set-header": "set-value",
			},
		}

		var capturedMD metadata.MD
		handler := func(ctx context.Context, req interface{}) (interface{}, error) {
			capturedMD, _ = metadata.FromIncomingContext(ctx)
			return "response", nil
		}

		interceptor := UnaryMetadataInterceptor(config)

		md := metadata.MD{
			"x-set-header": []string{"original-value"},
		}
		ctx := metadata.NewIncomingContext(context.Background(), md)
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

		resp, err := interceptor(ctx, "request", info, handler)

		assert.NoError(t, err)
		assert.Equal(t, "response", resp)
		assert.Equal(t, []string{"set-value"}, capturedMD.Get("x-set-header"))
	})

	t.Run("removes metadata", func(t *testing.T) {
		config := &MetadataConfig{
			Remove: []string{"x-remove-header"},
		}

		var capturedMD metadata.MD
		handler := func(ctx context.Context, req interface{}) (interface{}, error) {
			capturedMD, _ = metadata.FromIncomingContext(ctx)
			return "response", nil
		}

		interceptor := UnaryMetadataInterceptor(config)

		md := metadata.MD{
			"x-remove-header": []string{"to-be-removed"},
			"x-keep-header":   []string{"keep-value"},
		}
		ctx := metadata.NewIncomingContext(context.Background(), md)
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

		resp, err := interceptor(ctx, "request", info, handler)

		assert.NoError(t, err)
		assert.Equal(t, "response", resp)
		assert.Empty(t, capturedMD.Get("x-remove-header"))
		assert.Contains(t, capturedMD.Get("x-keep-header"), "keep-value")
	})
}

// TestStreamMetadataInterceptor tests the stream metadata interceptor
func TestStreamMetadataInterceptor(t *testing.T) {
	t.Parallel()

	t.Run("passes with nil config", func(t *testing.T) {
		interceptor := StreamMetadataInterceptor(nil)

		ctx := context.Background()
		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{FullMethod: "/test.Service/Method"}

		err := interceptor(nil, stream, info, mockStreamHandler)

		assert.NoError(t, err)
	})

	t.Run("modifies metadata for stream", func(t *testing.T) {
		config := &MetadataConfig{
			Add: map[string]string{
				"x-stream-header": "stream-value",
			},
		}

		var capturedMD metadata.MD
		handler := func(srv interface{}, ss grpc.ServerStream) error {
			capturedMD, _ = metadata.FromIncomingContext(ss.Context())
			return nil
		}

		interceptor := StreamMetadataInterceptor(config)

		ctx := context.Background()
		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{FullMethod: "/test.Service/Method"}

		err := interceptor(nil, stream, info, handler)

		assert.NoError(t, err)
		assert.Contains(t, capturedMD.Get("x-stream-header"), "stream-value")
	})
}

// TestModifyIncomingMetadata tests the modifyIncomingMetadata function
func TestModifyIncomingMetadata(t *testing.T) {
	t.Parallel()

	t.Run("creates metadata when none exists", func(t *testing.T) {
		config := &MetadataConfig{
			Add: map[string]string{
				"x-new-header": "new-value",
			},
		}

		ctx := modifyIncomingMetadata(context.Background(), config)

		md, ok := metadata.FromIncomingContext(ctx)
		assert.True(t, ok)
		assert.Contains(t, md.Get("x-new-header"), "new-value")
	})

	t.Run("preserves existing metadata", func(t *testing.T) {
		config := &MetadataConfig{
			Add: map[string]string{
				"x-new-header": "new-value",
			},
		}

		originalMD := metadata.MD{
			"x-existing-header": []string{"existing-value"},
		}
		ctx := metadata.NewIncomingContext(context.Background(), originalMD)

		ctx = modifyIncomingMetadata(ctx, config)

		md, ok := metadata.FromIncomingContext(ctx)
		assert.True(t, ok)
		assert.Contains(t, md.Get("x-existing-header"), "existing-value")
		assert.Contains(t, md.Get("x-new-header"), "new-value")
	})

	t.Run("applies operations in correct order", func(t *testing.T) {
		config := &MetadataConfig{
			Remove: []string{"x-remove"},
			Set:    map[string]string{"x-set": "set-value"},
			Add:    map[string]string{"x-add": "add-value"},
		}

		originalMD := metadata.MD{
			"x-remove": []string{"to-remove"},
			"x-set":    []string{"original"},
		}
		ctx := metadata.NewIncomingContext(context.Background(), originalMD)

		ctx = modifyIncomingMetadata(ctx, config)

		md, _ := metadata.FromIncomingContext(ctx)
		assert.Empty(t, md.Get("x-remove"))
		assert.Equal(t, []string{"set-value"}, md.Get("x-set"))
		assert.Contains(t, md.Get("x-add"), "add-value")
	})
}

// TestMetadataServerStream tests the metadata server stream wrapper
func TestMetadataServerStream(t *testing.T) {
	t.Parallel()

	ctx := context.WithValue(context.Background(), "test", "value")
	baseStream := &mockServerStream{ctx: context.Background()}

	wrappedStream := &metadataServerStream{
		ServerStream: baseStream,
		ctx:          ctx,
	}

	t.Run("returns wrapped context", func(t *testing.T) {
		returnedCtx := wrappedStream.Context()
		assert.Equal(t, "value", returnedCtx.Value("test"))
	})
}

// TestUnaryResponseMetadataInterceptor tests the unary response metadata interceptor
func TestUnaryResponseMetadataInterceptor(t *testing.T) {
	t.Parallel()

	t.Run("passes with nil config", func(t *testing.T) {
		interceptor := UnaryResponseMetadataInterceptor(nil)

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

		resp, err := interceptor(ctx, "request", info, mockUnaryHandler)

		assert.NoError(t, err)
		assert.Equal(t, "response", resp)
	})

	t.Run("sends headers", func(t *testing.T) {
		config := &ResponseMetadataConfig{
			Headers: map[string]string{
				"x-response-header": "response-value",
			},
		}

		interceptor := UnaryResponseMetadataInterceptor(config)

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

		resp, err := interceptor(ctx, "request", info, mockUnaryHandler)

		assert.NoError(t, err)
		assert.Equal(t, "response", resp)
	})

	t.Run("sets trailers", func(t *testing.T) {
		config := &ResponseMetadataConfig{
			Trailers: map[string]string{
				"x-trailer": "trailer-value",
			},
		}

		interceptor := UnaryResponseMetadataInterceptor(config)

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

		resp, err := interceptor(ctx, "request", info, mockUnaryHandler)

		assert.NoError(t, err)
		assert.Equal(t, "response", resp)
	})
}

// TestStreamResponseMetadataInterceptor tests the stream response metadata interceptor
func TestStreamResponseMetadataInterceptor(t *testing.T) {
	t.Parallel()

	t.Run("passes with nil config", func(t *testing.T) {
		interceptor := StreamResponseMetadataInterceptor(nil)

		ctx := context.Background()
		stream := &mockServerStreamWithHeader{
			mockServerStream: mockServerStream{ctx: ctx},
		}
		info := &grpc.StreamServerInfo{FullMethod: "/test.Service/Method"}

		err := interceptor(nil, stream, info, mockStreamHandler)

		assert.NoError(t, err)
	})

	t.Run("sends headers for stream", func(t *testing.T) {
		config := &ResponseMetadataConfig{
			Headers: map[string]string{
				"x-stream-response-header": "stream-response-value",
			},
		}

		var sentHeaders metadata.MD
		stream := &mockServerStreamWithHeader{
			mockServerStream: mockServerStream{ctx: context.Background()},
			onSendHeader: func(md metadata.MD) {
				sentHeaders = md
			},
		}

		interceptor := StreamResponseMetadataInterceptor(config)

		info := &grpc.StreamServerInfo{FullMethod: "/test.Service/Method"}

		err := interceptor(nil, stream, info, mockStreamHandler)

		assert.NoError(t, err)
		assert.Contains(t, sentHeaders.Get("x-stream-response-header"), "stream-response-value")
	})
}

// mockServerStreamWithHeader extends mockServerStream with header handling
type mockServerStreamWithHeader struct {
	mockServerStream
	onSendHeader func(md metadata.MD)
}

func (m *mockServerStreamWithHeader) SendHeader(md metadata.MD) error {
	if m.onSendHeader != nil {
		m.onSendHeader(md)
	}
	return nil
}

// TestResponseMetadataServerStream tests the response metadata server stream wrapper
func TestResponseMetadataServerStream(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	baseStream := &mockServerStreamWithTrailer{
		mockServerStream: mockServerStream{ctx: ctx},
	}

	trailers := map[string]string{
		"x-trailer": "trailer-value",
	}

	wrappedStream := &responseMetadataServerStream{
		ServerStream: baseStream,
		trailers:     trailers,
	}

	t.Run("adds configured trailers", func(t *testing.T) {
		md := metadata.MD{}
		wrappedStream.SetTrailer(md)

		assert.Contains(t, baseStream.lastTrailer.Get("x-trailer"), "trailer-value")
	})
}

// mockServerStreamWithTrailer extends mockServerStream with trailer handling
type mockServerStreamWithTrailer struct {
	mockServerStream
	lastTrailer metadata.MD
}

func (m *mockServerStreamWithTrailer) SetTrailer(md metadata.MD) {
	m.lastTrailer = md
}

// TestMetadataExtractor tests the MetadataExtractor
func TestMetadataExtractor(t *testing.T) {
	t.Parallel()

	t.Run("extracts specified keys", func(t *testing.T) {
		extractor := &MetadataExtractor{
			Keys: []string{"key1", "key2"},
		}

		md := metadata.MD{
			"key1": []string{"value1"},
			"key2": []string{"value2"},
			"key3": []string{"value3"},
		}

		result := extractor.Extract(md)

		assert.Len(t, result, 2)
		assert.Equal(t, "value1", result["key1"])
		assert.Equal(t, "value2", result["key2"])
		assert.NotContains(t, result, "key3")
	})

	t.Run("handles missing keys", func(t *testing.T) {
		extractor := &MetadataExtractor{
			Keys: []string{"missing-key"},
		}

		md := metadata.MD{
			"other-key": []string{"value"},
		}

		result := extractor.Extract(md)

		assert.Empty(t, result)
	})

	t.Run("handles empty keys", func(t *testing.T) {
		extractor := &MetadataExtractor{
			Keys: []string{},
		}

		md := metadata.MD{
			"key": []string{"value"},
		}

		result := extractor.Extract(md)

		assert.Empty(t, result)
	})
}

// TestMetadataFromContext tests MetadataFromContext function
func TestMetadataFromContext(t *testing.T) {
	t.Parallel()

	t.Run("returns metadata from context", func(t *testing.T) {
		md := metadata.MD{
			"key": []string{"value"},
		}
		ctx := metadata.NewIncomingContext(context.Background(), md)

		result := MetadataFromContext(ctx)

		assert.Equal(t, []string{"value"}, result.Get("key"))
	})

	t.Run("returns empty metadata when none exists", func(t *testing.T) {
		result := MetadataFromContext(context.Background())

		assert.NotNil(t, result)
		assert.Empty(t, result)
	})
}

// TestGetMetadataValue tests GetMetadataValue function
func TestGetMetadataValue(t *testing.T) {
	t.Parallel()

	t.Run("returns value for existing key", func(t *testing.T) {
		md := metadata.MD{
			"key": []string{"value"},
		}
		ctx := metadata.NewIncomingContext(context.Background(), md)

		result := GetMetadataValue(ctx, "key")

		assert.Equal(t, "value", result)
	})

	t.Run("returns empty for missing key", func(t *testing.T) {
		md := metadata.MD{}
		ctx := metadata.NewIncomingContext(context.Background(), md)

		result := GetMetadataValue(ctx, "missing")

		assert.Empty(t, result)
	})

	t.Run("returns empty when no metadata", func(t *testing.T) {
		result := GetMetadataValue(context.Background(), "key")

		assert.Empty(t, result)
	})

	t.Run("handles case-insensitive keys", func(t *testing.T) {
		md := metadata.MD{
			"x-custom-header": []string{"value"},
		}
		ctx := metadata.NewIncomingContext(context.Background(), md)

		result := GetMetadataValue(ctx, "X-Custom-Header")

		assert.Equal(t, "value", result)
	})
}

// TestSetOutgoingMetadata tests SetOutgoingMetadata function
func TestSetOutgoingMetadata(t *testing.T) {
	t.Parallel()

	ctx := SetOutgoingMetadata(context.Background(), "key", "value")

	md, ok := metadata.FromOutgoingContext(ctx)
	assert.True(t, ok)
	assert.Contains(t, md.Get("key"), "value")
}

// TestCopyMetadata tests CopyMetadata function
func TestCopyMetadata(t *testing.T) {
	t.Parallel()

	t.Run("copies specified keys", func(t *testing.T) {
		incomingMD := metadata.MD{
			"key1": []string{"value1"},
			"key2": []string{"value2"},
			"key3": []string{"value3"},
		}
		ctx := metadata.NewIncomingContext(context.Background(), incomingMD)

		ctx = CopyMetadata(ctx, "key1", "key2")

		outgoingMD, ok := metadata.FromOutgoingContext(ctx)
		assert.True(t, ok)
		assert.Contains(t, outgoingMD.Get("key1"), "value1")
		assert.Contains(t, outgoingMD.Get("key2"), "value2")
		assert.Empty(t, outgoingMD.Get("key3"))
	})

	t.Run("handles missing keys", func(t *testing.T) {
		incomingMD := metadata.MD{
			"key1": []string{"value1"},
		}
		ctx := metadata.NewIncomingContext(context.Background(), incomingMD)

		ctx = CopyMetadata(ctx, "missing-key")

		_, ok := metadata.FromOutgoingContext(ctx)
		assert.False(t, ok)
	})

	t.Run("handles no incoming metadata", func(t *testing.T) {
		ctx := CopyMetadata(context.Background(), "key")

		_, ok := metadata.FromOutgoingContext(ctx)
		assert.False(t, ok)
	})

	t.Run("handles empty keys", func(t *testing.T) {
		incomingMD := metadata.MD{
			"key": []string{"value"},
		}
		ctx := metadata.NewIncomingContext(context.Background(), incomingMD)

		ctx = CopyMetadata(ctx)

		_, ok := metadata.FromOutgoingContext(ctx)
		assert.False(t, ok)
	})
}

// TestMetadataConfig tests MetadataConfig struct
func TestMetadataConfig(t *testing.T) {
	t.Parallel()

	t.Run("default values", func(t *testing.T) {
		config := MetadataConfig{}

		assert.Nil(t, config.Add)
		assert.Nil(t, config.Remove)
		assert.Nil(t, config.Set)
	})

	t.Run("with all fields", func(t *testing.T) {
		config := MetadataConfig{
			Add:    map[string]string{"add-key": "add-value"},
			Remove: []string{"remove-key"},
			Set:    map[string]string{"set-key": "set-value"},
		}

		assert.Len(t, config.Add, 1)
		assert.Len(t, config.Remove, 1)
		assert.Len(t, config.Set, 1)
	})
}

// TestResponseMetadataConfig tests ResponseMetadataConfig struct
func TestResponseMetadataConfig(t *testing.T) {
	t.Parallel()

	t.Run("default values", func(t *testing.T) {
		config := ResponseMetadataConfig{}

		assert.Nil(t, config.Headers)
		assert.Nil(t, config.Trailers)
	})

	t.Run("with all fields", func(t *testing.T) {
		config := ResponseMetadataConfig{
			Headers:  map[string]string{"header-key": "header-value"},
			Trailers: map[string]string{"trailer-key": "trailer-value"},
		}

		assert.Len(t, config.Headers, 1)
		assert.Len(t, config.Trailers, 1)
	})
}
