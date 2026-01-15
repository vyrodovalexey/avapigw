package interceptor

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// MetadataConfig holds configuration for metadata manipulation.
type MetadataConfig struct {
	// Add adds new metadata entries.
	Add map[string]string
	// Remove removes metadata entries by key.
	Remove []string
	// Set sets metadata entries (overwrites existing).
	Set map[string]string
}

// UnaryMetadataInterceptor returns a unary interceptor that manipulates metadata.
func UnaryMetadataInterceptor(config *MetadataConfig) grpc.UnaryServerInterceptor {
	if config == nil {
		config = &MetadataConfig{}
	}

	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// Modify incoming metadata
		ctx = modifyIncomingMetadata(ctx, config)

		// Process request
		resp, err := handler(ctx, req)

		return resp, err
	}
}

// StreamMetadataInterceptor returns a stream interceptor that manipulates metadata.
func StreamMetadataInterceptor(config *MetadataConfig) grpc.StreamServerInterceptor {
	if config == nil {
		config = &MetadataConfig{}
	}

	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		// Wrap the stream with modified context
		wrappedStream := &metadataServerStream{
			ServerStream: ss,
			ctx:          modifyIncomingMetadata(ss.Context(), config),
		}

		return handler(srv, wrappedStream)
	}
}

// modifyIncomingMetadata modifies the incoming metadata based on the config.
func modifyIncomingMetadata(ctx context.Context, config *MetadataConfig) context.Context {
	// Get existing metadata
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		md = metadata.MD{}
	} else {
		// Create a copy to avoid modifying the original
		md = md.Copy()
	}

	// Remove entries
	for _, key := range config.Remove {
		delete(md, strings.ToLower(key))
	}

	// Set entries (overwrite)
	for key, value := range config.Set {
		md.Set(strings.ToLower(key), value)
	}

	// Add entries (append)
	for key, value := range config.Add {
		md.Append(strings.ToLower(key), value)
	}

	// Create new context with modified metadata
	return metadata.NewIncomingContext(ctx, md)
}

// metadataServerStream wraps a grpc.ServerStream with a modified context.
type metadataServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

// Context returns the wrapped context.
func (s *metadataServerStream) Context() context.Context {
	return s.ctx
}

// ResponseMetadataConfig holds configuration for response metadata manipulation.
type ResponseMetadataConfig struct {
	// Headers are metadata entries to send as headers.
	Headers map[string]string
	// Trailers are metadata entries to send as trailers.
	Trailers map[string]string
}

// UnaryResponseMetadataInterceptor returns a unary interceptor that adds response metadata.
func UnaryResponseMetadataInterceptor(config *ResponseMetadataConfig) grpc.UnaryServerInterceptor {
	if config == nil {
		config = &ResponseMetadataConfig{}
	}

	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// Send headers
		if len(config.Headers) > 0 {
			md := metadata.MD{}
			for key, value := range config.Headers {
				md.Set(strings.ToLower(key), value)
			}
			_ = grpc.SendHeader(ctx, md) // Explicitly ignore error as headers may already be sent
		}

		// Process request
		resp, err := handler(ctx, req)

		// Set trailers
		if len(config.Trailers) > 0 {
			md := metadata.MD{}
			for key, value := range config.Trailers {
				md.Set(strings.ToLower(key), value)
			}
			_ = grpc.SetTrailer(ctx, md) // Explicitly ignore error as trailers are best-effort
		}

		return resp, err
	}
}

// StreamResponseMetadataInterceptor returns a stream interceptor that adds response metadata.
func StreamResponseMetadataInterceptor(config *ResponseMetadataConfig) grpc.StreamServerInterceptor {
	if config == nil {
		config = &ResponseMetadataConfig{}
	}

	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		// Send headers
		if len(config.Headers) > 0 {
			md := metadata.MD{}
			for key, value := range config.Headers {
				md.Set(strings.ToLower(key), value)
			}
			_ = ss.SendHeader(md) // Explicitly ignore error as headers may already be sent
		}

		// Wrap stream to set trailers
		wrappedStream := &responseMetadataServerStream{
			ServerStream: ss,
			trailers:     config.Trailers,
		}

		return handler(srv, wrappedStream)
	}
}

// responseMetadataServerStream wraps a grpc.ServerStream to add trailers.
type responseMetadataServerStream struct {
	grpc.ServerStream
	trailers map[string]string
}

// SetTrailer adds the configured trailers.
func (s *responseMetadataServerStream) SetTrailer(md metadata.MD) {
	// Add configured trailers
	for key, value := range s.trailers {
		md.Set(strings.ToLower(key), value)
	}
	s.ServerStream.SetTrailer(md)
}

// MetadataExtractor extracts values from metadata.
type MetadataExtractor struct {
	// Keys are the metadata keys to extract.
	Keys []string
}

// Extract extracts values from metadata.
func (e *MetadataExtractor) Extract(md metadata.MD) map[string]string {
	result := make(map[string]string)
	for _, key := range e.Keys {
		if values := md.Get(strings.ToLower(key)); len(values) > 0 {
			result[key] = values[0]
		}
	}
	return result
}

// MetadataFromContext extracts metadata from context.
func MetadataFromContext(ctx context.Context) metadata.MD {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return metadata.MD{}
	}
	return md
}

// GetMetadataValue gets a single metadata value from context.
func GetMetadataValue(ctx context.Context, key string) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	values := md.Get(strings.ToLower(key))
	if len(values) > 0 {
		return values[0]
	}
	return ""
}

// SetOutgoingMetadata sets metadata on the outgoing context.
func SetOutgoingMetadata(ctx context.Context, key, value string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, strings.ToLower(key), value)
}

// CopyMetadata copies metadata from incoming to outgoing context.
func CopyMetadata(ctx context.Context, keys ...string) context.Context {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ctx
	}

	pairs := make([]string, 0)
	for _, key := range keys {
		if values := md.Get(strings.ToLower(key)); len(values) > 0 {
			pairs = append(pairs, strings.ToLower(key), values[0])
		}
	}

	if len(pairs) > 0 {
		return metadata.AppendToOutgoingContext(ctx, pairs...)
	}
	return ctx
}
