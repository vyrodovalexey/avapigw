// Package encoding provides encoding/decoding capabilities for the API Gateway.
package encoding

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

// jsonCodec implements Codec for JSON encoding.
type jsonCodec struct {
	cfg *config.JSONEncodingConfig
}

// NewJSONCodec creates a new JSON codec.
func NewJSONCodec(cfg *config.JSONEncodingConfig) Codec {
	if cfg == nil {
		cfg = &config.JSONEncodingConfig{}
	}
	return &jsonCodec{cfg: cfg}
}

// Encode encodes the value to JSON bytes.
func (c *jsonCodec) Encode(v interface{}) ([]byte, error) {
	if v == nil {
		return nil, ErrNilValue
	}

	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)

	// Configure encoder based on settings
	if c.cfg.PrettyPrint {
		encoder.SetIndent("", "  ")
	}

	// Note: EmitDefaults, UseProtoNames, EnumAsIntegers, Int64AsStrings
	// would require custom marshaling logic or protojson for protobuf messages

	if err := encoder.Encode(v); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEncodingFailed, err)
	}

	// Remove trailing newline added by encoder
	result := buf.Bytes()
	if len(result) > 0 && result[len(result)-1] == '\n' {
		result = result[:len(result)-1]
	}

	return result, nil
}

// Decode decodes JSON bytes into the value.
func (c *jsonCodec) Decode(data []byte, v interface{}) error {
	if len(data) == 0 {
		return nil
	}

	decoder := json.NewDecoder(bytes.NewReader(data))

	// Use number type for better precision
	decoder.UseNumber()

	if err := decoder.Decode(v); err != nil {
		return fmt.Errorf("%w: %w", ErrDecodingFailed, err)
	}

	return nil
}

// ContentType returns the JSON content type.
func (c *jsonCodec) ContentType() string {
	return config.ContentTypeJSON
}

// MarshalJSON is a convenience function for JSON marshaling.
func MarshalJSON(v interface{}, pretty bool) ([]byte, error) {
	cfg := &config.JSONEncodingConfig{PrettyPrint: pretty}
	codec := NewJSONCodec(cfg)
	return codec.Encode(v)
}

// UnmarshalJSON is a convenience function for JSON unmarshaling.
func UnmarshalJSON(data []byte, v interface{}) error {
	codec := NewJSONCodec(nil)
	return codec.Decode(data, v)
}

// JSONToMap converts JSON bytes to a map.
func JSONToMap(data []byte) (map[string]interface{}, error) {
	var result map[string]interface{}
	if err := UnmarshalJSON(data, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// MapToJSON converts a map to JSON bytes.
func MapToJSON(m map[string]interface{}, pretty bool) ([]byte, error) {
	return MarshalJSON(m, pretty)
}
