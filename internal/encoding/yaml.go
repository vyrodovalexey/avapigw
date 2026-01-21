// Package encoding provides encoding/decoding capabilities for the API Gateway.
package encoding

import (
	"fmt"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"gopkg.in/yaml.v3"
)

// yamlCodec implements Codec for YAML encoding.
type yamlCodec struct{}

// NewYAMLCodec creates a new YAML codec.
func NewYAMLCodec() Codec {
	return &yamlCodec{}
}

// Encode encodes the value to YAML bytes.
func (c *yamlCodec) Encode(v interface{}) ([]byte, error) {
	if v == nil {
		return nil, ErrNilValue
	}

	data, err := yaml.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncodingFailed, err)
	}

	return data, nil
}

// Decode decodes YAML bytes into the value.
func (c *yamlCodec) Decode(data []byte, v interface{}) error {
	if len(data) == 0 {
		return nil
	}

	if err := yaml.Unmarshal(data, v); err != nil {
		return fmt.Errorf("%w: %v", ErrDecodingFailed, err)
	}

	return nil
}

// ContentType returns the YAML content type.
func (c *yamlCodec) ContentType() string {
	return config.ContentTypeYAML
}

// MarshalYAML is a convenience function for YAML marshaling.
func MarshalYAML(v interface{}) ([]byte, error) {
	codec := NewYAMLCodec()
	return codec.Encode(v)
}

// UnmarshalYAML is a convenience function for YAML unmarshaling.
func UnmarshalYAMLData(data []byte, v interface{}) error {
	codec := NewYAMLCodec()
	return codec.Decode(data, v)
}

// YAMLToMap converts YAML bytes to a map.
func YAMLToMap(data []byte) (map[string]interface{}, error) {
	var result map[string]interface{}
	if err := UnmarshalYAMLData(data, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// MapToYAML converts a map to YAML bytes.
func MapToYAML(m map[string]interface{}) ([]byte, error) {
	return MarshalYAML(m)
}
