// Package transform provides data transformation capabilities for the API Gateway.
//
// The transform package implements field filtering, mapping, grouping, flattening,
// array manipulation, and templating for both HTTP and gRPC requests/responses.
//
// # Features
//
//   - Field filtering using allow/deny lists
//   - Field mapping/renaming
//   - Field grouping into nested objects
//   - Field flattening from nested objects
//   - Array operations (filter, sort, limit, deduplicate)
//   - Response templating using Go templates
//   - Response merging for multiple backends
//
// # Example Usage
//
//	cfg := &config.ResponseTransformConfig{
//	    AllowFields: []string{"id", "name", "email"},
//	    FieldMappings: []config.FieldMapping{
//	        {Source: "user_id", Target: "id"},
//	    },
//	}
//
//	transformer := transform.NewResponseTransformer(logger)
//	result, err := transformer.TransformResponse(ctx, data, cfg)
//
// # Thread Safety
//
// All transformers are safe for concurrent use.
package transform
