// Package encoding provides encoding/decoding capabilities for the API Gateway.
package encoding

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

func TestNewYAMLCodec(t *testing.T) {
	codec := NewYAMLCodec()
	assert.NotNil(t, codec)
}

func TestYAMLCodec_Encode(t *testing.T) {
	tests := []struct {
		name        string
		value       interface{}
		wantErr     bool
		errType     error
		checkResult func(t *testing.T, data []byte)
	}{
		{
			name:  "encode map",
			value: map[string]interface{}{"name": "test", "value": 123},
			checkResult: func(t *testing.T, data []byte) {
				assert.Contains(t, string(data), "name: test")
				assert.Contains(t, string(data), "value: 123")
			},
		},
		{
			name: "encode struct",
			value: struct {
				Name  string `yaml:"name"`
				Value int    `yaml:"value"`
			}{Name: "test", Value: 123},
			checkResult: func(t *testing.T, data []byte) {
				assert.Contains(t, string(data), "name: test")
				assert.Contains(t, string(data), "value: 123")
			},
		},
		{
			name:  "encode slice",
			value: []string{"a", "b", "c"},
			checkResult: func(t *testing.T, data []byte) {
				assert.Contains(t, string(data), "- a")
				assert.Contains(t, string(data), "- b")
				assert.Contains(t, string(data), "- c")
			},
		},
		{
			name:    "encode nil",
			value:   nil,
			wantErr: true,
			errType: ErrNilValue,
		},
		{
			name:  "encode string",
			value: "hello world",
			checkResult: func(t *testing.T, data []byte) {
				assert.Contains(t, string(data), "hello world")
			},
		},
		{
			name:  "encode number",
			value: 42,
			checkResult: func(t *testing.T, data []byte) {
				assert.Contains(t, string(data), "42")
			},
		},
		{
			name:  "encode boolean",
			value: true,
			checkResult: func(t *testing.T, data []byte) {
				assert.Contains(t, string(data), "true")
			},
		},
		{
			name: "encode nested structure",
			value: map[string]interface{}{
				"outer": map[string]interface{}{
					"inner": "value",
				},
			},
			checkResult: func(t *testing.T, data []byte) {
				assert.Contains(t, string(data), "outer:")
				assert.Contains(t, string(data), "inner: value")
			},
		},
		{
			name:  "encode empty map",
			value: map[string]interface{}{},
			checkResult: func(t *testing.T, data []byte) {
				assert.Contains(t, string(data), "{}")
			},
		},
		{
			name:  "encode empty slice",
			value: []string{},
			checkResult: func(t *testing.T, data []byte) {
				assert.Contains(t, string(data), "[]")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			codec := NewYAMLCodec()
			data, err := codec.Encode(tt.value)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errType != nil {
					assert.ErrorIs(t, err, tt.errType)
				}
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, data)
				if tt.checkResult != nil {
					tt.checkResult(t, data)
				}
			}
		})
	}
}

func TestYAMLCodec_Decode(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		target      interface{}
		wantErr     bool
		checkResult func(t *testing.T, target interface{})
	}{
		{
			name:   "decode to map",
			data:   []byte("name: test\nvalue: 123"),
			target: &map[string]interface{}{},
			checkResult: func(t *testing.T, target interface{}) {
				m := target.(*map[string]interface{})
				assert.Equal(t, "test", (*m)["name"])
				assert.Equal(t, 123, (*m)["value"])
			},
		},
		{
			name: "decode to struct",
			data: []byte("name: test\nvalue: 123"),
			target: &struct {
				Name  string `yaml:"name"`
				Value int    `yaml:"value"`
			}{},
			checkResult: func(t *testing.T, target interface{}) {
				s := target.(*struct {
					Name  string `yaml:"name"`
					Value int    `yaml:"value"`
				})
				assert.Equal(t, "test", s.Name)
				assert.Equal(t, 123, s.Value)
			},
		},
		{
			name:   "decode to slice",
			data:   []byte("- a\n- b\n- c"),
			target: &[]string{},
			checkResult: func(t *testing.T, target interface{}) {
				s := target.(*[]string)
				assert.Equal(t, []string{"a", "b", "c"}, *s)
			},
		},
		{
			name:    "decode empty data",
			data:    []byte{},
			target:  &map[string]interface{}{},
			wantErr: false,
		},
		{
			name:    "decode invalid YAML",
			data:    []byte("invalid: yaml: content: ["),
			target:  &map[string]interface{}{},
			wantErr: true,
		},
		{
			name:   "decode nested structure",
			data:   []byte("outer:\n  inner: value"),
			target: &map[string]interface{}{},
			checkResult: func(t *testing.T, target interface{}) {
				m := target.(*map[string]interface{})
				outer := (*m)["outer"].(map[string]interface{})
				assert.Equal(t, "value", outer["inner"])
			},
		},
		{
			name:   "decode with anchors and aliases",
			data:   []byte("defaults: &defaults\n  name: test\nitem:\n  <<: *defaults\n  value: 123"),
			target: &map[string]interface{}{},
			checkResult: func(t *testing.T, target interface{}) {
				m := target.(*map[string]interface{})
				item := (*m)["item"].(map[string]interface{})
				assert.Equal(t, "test", item["name"])
				assert.Equal(t, 123, item["value"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			codec := NewYAMLCodec()
			err := codec.Decode(tt.data, tt.target)

			if tt.wantErr {
				require.Error(t, err)
				assert.ErrorIs(t, err, ErrDecodingFailed)
			} else {
				require.NoError(t, err)
				if tt.checkResult != nil {
					tt.checkResult(t, tt.target)
				}
			}
		})
	}
}

func TestYAMLCodec_ContentType(t *testing.T) {
	codec := NewYAMLCodec()
	assert.Equal(t, config.ContentTypeYAML, codec.ContentType())
}

func TestMarshalYAML(t *testing.T) {
	tests := []struct {
		name    string
		value   interface{}
		wantErr bool
	}{
		{
			name:    "marshal map",
			value:   map[string]interface{}{"name": "test"},
			wantErr: false,
		},
		{
			name:    "marshal nil",
			value:   nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := MarshalYAML(tt.value)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, data)
			}
		})
	}
}

func TestUnmarshalYAMLData(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "unmarshal valid YAML",
			data:    []byte("name: test"),
			wantErr: false,
		},
		{
			name:    "unmarshal empty data",
			data:    []byte{},
			wantErr: false,
		},
		{
			name:    "unmarshal invalid YAML",
			data:    []byte("invalid: yaml: ["),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result map[string]interface{}
			err := UnmarshalYAMLData(tt.data, &result)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestYAMLToMap(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
		check   func(t *testing.T, result map[string]interface{})
	}{
		{
			name:    "valid YAML object",
			data:    []byte("name: test\nvalue: 123"),
			wantErr: false,
			check: func(t *testing.T, result map[string]interface{}) {
				assert.Equal(t, "test", result["name"])
				assert.Equal(t, 123, result["value"])
			},
		},
		{
			name:    "empty YAML",
			data:    []byte{},
			wantErr: false,
			check: func(t *testing.T, result map[string]interface{}) {
				assert.Nil(t, result)
			},
		},
		{
			name:    "invalid YAML",
			data:    []byte("invalid: yaml: ["),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := YAMLToMap(tt.data)

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

func TestMapToYAML(t *testing.T) {
	tests := []struct {
		name    string
		m       map[string]interface{}
		wantErr bool
	}{
		{
			name:    "simple map",
			m:       map[string]interface{}{"name": "test"},
			wantErr: false,
		},
		{
			name:    "nil map",
			m:       nil,
			wantErr: false, // nil map encodes to "null"
		},
		{
			name:    "empty map",
			m:       map[string]interface{}{},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := MapToYAML(tt.m)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, data)
			}
		})
	}
}

func TestYAMLCodec_RoundTrip(t *testing.T) {
	codec := NewYAMLCodec()

	original := map[string]interface{}{
		"string": "hello",
		"number": 42,
		"bool":   true,
		"nested": map[string]interface{}{
			"key": "value",
		},
		"array": []interface{}{"a", "b", "c"},
	}

	// Encode
	data, err := codec.Encode(original)
	require.NoError(t, err)

	// Decode
	var decoded map[string]interface{}
	err = codec.Decode(data, &decoded)
	require.NoError(t, err)

	// Verify
	assert.Equal(t, original["string"], decoded["string"])
	assert.Equal(t, original["number"], decoded["number"])
	assert.Equal(t, original["bool"], decoded["bool"])
}

func TestYAMLCodec_MultiDocument(t *testing.T) {
	codec := NewYAMLCodec()

	// YAML with multiple documents (only first is decoded)
	data := []byte("---\nname: first\n---\nname: second")

	var result map[string]interface{}
	err := codec.Decode(data, &result)
	require.NoError(t, err)

	// Should decode the first document
	assert.Equal(t, "first", result["name"])
}

func TestYAMLCodec_SpecialCharacters(t *testing.T) {
	codec := NewYAMLCodec()

	tests := []struct {
		name  string
		value map[string]interface{}
	}{
		{
			name:  "with colon in value",
			value: map[string]interface{}{"url": "http://example.com"},
		},
		{
			name:  "with quotes in value",
			value: map[string]interface{}{"message": `He said "hello"`},
		},
		{
			name:  "with newlines in value",
			value: map[string]interface{}{"text": "line1\nline2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode
			data, err := codec.Encode(tt.value)
			require.NoError(t, err)

			// Decode
			var decoded map[string]interface{}
			err = codec.Decode(data, &decoded)
			require.NoError(t, err)

			// Values should match
			for k, v := range tt.value {
				assert.Equal(t, v, decoded[k])
			}
		})
	}
}
