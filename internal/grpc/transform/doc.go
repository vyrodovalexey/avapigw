// Package transform provides gRPC-specific data transformation capabilities.
//
// It supports Protocol Buffer message transformation, FieldMask-based filtering,
// streaming transformation, and metadata manipulation.
//
// # Features
//
//   - Protocol Buffer message transformation using reflection
//   - FieldMask-based field filtering and selection
//   - Streaming message transformation with rate limiting
//   - gRPC metadata transformation (headers and trailers)
//   - Field injection and removal
//   - Repeated field operations (filter, sort, limit, deduplicate)
//   - Map field operations (filter keys, merge)
//
// # Example Usage
//
//	cfg := &config.GRPCTransformConfig{
//	    Response: &config.GRPCResponseTransformConfig{
//	        FieldMask: []string{"user.name", "user.email"},
//	    },
//	}
//
//	transformer := transform.NewProtobufTransformer(logger)
//	result, err := transformer.TransformMessage(ctx, msg, cfg)
//
// # Thread Safety
//
// All transformers are safe for concurrent use. The StreamingTransformer
// maintains per-stream state and should be created for each stream.
package transform
