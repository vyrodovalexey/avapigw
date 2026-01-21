// Package encoding provides encoding/decoding capabilities for the API Gateway.
package encoding

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

func TestNewJSONCodec(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config.JSONEncodingConfig
	}{
		{
			name: "nil config",
			cfg:  nil,
		},
		{
			name: "empty config",
			cfg:  &config.JSONEncodingConfig{},
		},
		{
			name: "with pretty print",
			cfg: &config.JSONEncodingConfig{
				PrettyPrint: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			codec := NewJSONCodec(tt.cfg)
			assert.NotNil(t, codec)
		})
	}
}

func TestJSONCodec_Encode(t *testing.T) {
	tests := []struct {
		name        string
		cfg         *config.JSONEncodingConfig
		value       interface{}
		wantErr     bool
		errType     error
		checkResult func(t *testing.T, data []byte)
	}{
		{
			name:  "encode map",
			cfg:   nil,
			value: map[string]interface{}{"name": "test", "value": 123},
			checkResult: func(t *testing.T, data []byte) {
				var result map[string]interface{}
				err := json.Unmarshal(data, &result)
				require.NoError(t, err)
				assert.Equal(t, "test", result["name"])
			},
		},
		{
			name:  "encode struct",
			cfg:   nil,
			value: struct{ Name string }{Name: "test"},
			checkResult: func(t *testing.T, data []byte) {
				assert.Contains(t, string(data), "Name")
				assert.Contains(t, string(data), "test")
			},
		},
		{
			name:  "encode slice",
			cfg:   nil,
			value: []string{"a", "b", "c"},
			checkResult: func(t *testing.T, data []byte) {
				var result []string
				err := json.Unmarshal(data, &result)
				require.NoError(t, err)
				assert.Equal(t, []string{"a", "b", "c"}, result)
			},
		},
		{
			name:    "encode nil",
			cfg:     nil,
			value:   nil,
			wantErr: true,
			errType: ErrNilValue,
		},
		{
			name: "encode with pretty print",
			cfg: &config.JSONEncodingConfig{
				PrettyPrint: true,
			},
			value: map[string]interface{}{"name": "test"},
			checkResult: func(t *testing.T, data []byte) {
				// Pretty printed JSON should contain newlines and indentation
				assert.Contains(t, string(data), "\n")
				assert.Contains(t, string(data), "  ")
			},
		},
		{
			name: "encode without pretty print",
			cfg: &config.JSONEncodingConfig{
				PrettyPrint: false,
			},
			value: map[string]interface{}{"name": "test"},
			checkResult: func(t *testing.T, data []byte) {
				// Compact JSON should not contain newlines
				assert.NotContains(t, string(data), "\n")
			},
		},
		{
			name:  "encode string",
			cfg:   nil,
			value: "hello world",
			checkResult: func(t *testing.T, data []byte) {
				assert.Equal(t, `"hello world"`, string(data))
			},
		},
		{
			name:  "encode number",
			cfg:   nil,
			value: 42,
			checkResult: func(t *testing.T, data []byte) {
				assert.Equal(t, "42", string(data))
			},
		},
		{
			name:  "encode boolean",
			cfg:   nil,
			value: true,
			checkResult: func(t *testing.T, data []byte) {
				assert.Equal(t, "true", string(data))
			},
		},
		{
			name:  "encode nested structure",
			cfg:   nil,
			value: map[string]interface{}{"outer": map[string]interface{}{"inner": "value"}},
			checkResult: func(t *testing.T, data []byte) {
				var result map[string]interface{}
				err := json.Unmarshal(data, &result)
				require.NoError(t, err)
				outer := result["outer"].(map[string]interface{})
				assert.Equal(t, "value", outer["inner"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			codec := NewJSONCodec(tt.cfg)
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

func TestJSONCodec_Decode(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		target      interface{}
		wantErr     bool
		checkResult func(t *testing.T, target interface{})
	}{
		{
			name:   "decode to map",
			data:   []byte(`{"name":"test","value":123}`),
			target: &map[string]interface{}{},
			checkResult: func(t *testing.T, target interface{}) {
				m := target.(*map[string]interface{})
				assert.Equal(t, "test", (*m)["name"])
			},
		},
		{
			name:   "decode to struct",
			data:   []byte(`{"Name":"test"}`),
			target: &struct{ Name string }{},
			checkResult: func(t *testing.T, target interface{}) {
				s := target.(*struct{ Name string })
				assert.Equal(t, "test", s.Name)
			},
		},
		{
			name:   "decode to slice",
			data:   []byte(`["a","b","c"]`),
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
			name:    "decode invalid JSON",
			data:    []byte(`{invalid json}`),
			target:  &map[string]interface{}{},
			wantErr: true,
		},
		{
			name:   "decode with numbers",
			data:   []byte(`{"value":123456789012345678901234567890}`),
			target: &map[string]interface{}{},
			checkResult: func(t *testing.T, target interface{}) {
				m := target.(*map[string]interface{})
				// Should use json.Number for precision
				_, ok := (*m)["value"].(json.Number)
				assert.True(t, ok, "should use json.Number for large numbers")
			},
		},
		{
			name:   "decode nested structure",
			data:   []byte(`{"outer":{"inner":"value"}}`),
			target: &map[string]interface{}{},
			checkResult: func(t *testing.T, target interface{}) {
				m := target.(*map[string]interface{})
				outer := (*m)["outer"].(map[string]interface{})
				assert.Equal(t, "value", outer["inner"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			codec := NewJSONCodec(nil)
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

func TestJSONCodec_ContentType(t *testing.T) {
	codec := NewJSONCodec(nil)
	assert.Equal(t, config.ContentTypeJSON, codec.ContentType())
}

func TestMarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		value   interface{}
		pretty  bool
		wantErr bool
	}{
		{
			name:    "marshal map",
			value:   map[string]interface{}{"name": "test"},
			pretty:  false,
			wantErr: false,
		},
		{
			name:    "marshal with pretty print",
			value:   map[string]interface{}{"name": "test"},
			pretty:  true,
			wantErr: false,
		},
		{
			name:    "marshal nil",
			value:   nil,
			pretty:  false,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := MarshalJSON(tt.value, tt.pretty)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, data)

				if tt.pretty {
					assert.Contains(t, string(data), "\n")
				}
			}
		})
	}
}

func TestUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "unmarshal valid JSON",
			data:    []byte(`{"name":"test"}`),
			wantErr: false,
		},
		{
			name:    "unmarshal empty data",
			data:    []byte{},
			wantErr: false,
		},
		{
			name:    "unmarshal invalid JSON",
			data:    []byte(`{invalid}`),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result map[string]interface{}
			err := UnmarshalJSON(tt.data, &result)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestJSONToMap(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
		check   func(t *testing.T, result map[string]interface{})
	}{
		{
			name:    "valid JSON object",
			data:    []byte(`{"name":"test","value":123}`),
			wantErr: false,
			check: func(t *testing.T, result map[string]interface{}) {
				assert.Equal(t, "test", result["name"])
			},
		},
		{
			name:    "empty JSON object",
			data:    []byte(`{}`),
			wantErr: false,
			check: func(t *testing.T, result map[string]interface{}) {
				assert.Empty(t, result)
			},
		},
		{
			name:    "invalid JSON",
			data:    []byte(`{invalid}`),
			wantErr: true,
		},
		{
			name:    "JSON array (not object)",
			data:    []byte(`[1,2,3]`),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := JSONToMap(tt.data)

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

func TestMapToJSON(t *testing.T) {
	tests := []struct {
		name    string
		m       map[string]interface{}
		pretty  bool
		wantErr bool
	}{
		{
			name:    "simple map",
			m:       map[string]interface{}{"name": "test"},
			pretty:  false,
			wantErr: false,
		},
		{
			name:    "map with pretty print",
			m:       map[string]interface{}{"name": "test"},
			pretty:  true,
			wantErr: false,
		},
		{
			name:    "nil map",
			m:       nil,
			pretty:  false,
			wantErr: false, // nil map encodes to "null"
		},
		{
			name:    "empty map",
			m:       map[string]interface{}{},
			pretty:  false,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := MapToJSON(tt.m, tt.pretty)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, data)
			}
		})
	}
}

func TestJSONCodec_RoundTrip(t *testing.T) {
	codec := NewJSONCodec(nil)

	original := map[string]interface{}{
		"string": "hello",
		"number": float64(42),
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
	assert.Equal(t, original["bool"], decoded["bool"])
}
