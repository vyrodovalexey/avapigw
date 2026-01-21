// Package encoding provides encoding/decoding capabilities for the API Gateway.
//
// The encoding package implements codecs for various content types including:
//
//   - JSON (application/json)
//   - XML (application/xml)
//   - YAML (application/yaml)
//   - Protocol Buffers (application/protobuf)
//
// It also provides content type negotiation based on Accept headers.
//
// # Example Usage
//
//	// Create a JSON codec
//	codec := encoding.NewJSONCodec(nil)
//
//	// Encode data
//	data, err := codec.Encode(myStruct)
//
//	// Decode data
//	var result MyStruct
//	err = codec.Decode(data, &result)
//
//	// Content negotiation
//	negotiator := encoding.NewNegotiator([]string{"application/json", "application/xml"})
//	contentType := negotiator.Negotiate(acceptHeader)
//
// # Thread Safety
//
// All codecs and negotiators are safe for concurrent use.
package encoding
