//go:build functional
// +build functional

// Package functional contains functional tests for the API Gateway.
// These tests verify encoding/decoding logic in isolation.
package functional

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/encoding"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// TestFunctional_Encoding_JSON tests JSON encoding/decoding.
func TestFunctional_Encoding_JSON(t *testing.T) {
	t.Parallel()

	codec := encoding.NewJSONCodec(nil)

	t.Run("encode_simple_map", func(t *testing.T) {
		data := map[string]interface{}{
			"name": "Test",
			"id":   123,
		}

		encoded, err := codec.Encode(data)
		require.NoError(t, err)
		assert.Contains(t, string(encoded), `"name":"Test"`)
		assert.Contains(t, string(encoded), `"id":123`)
	})

	t.Run("decode_simple_map", func(t *testing.T) {
		jsonData := []byte(`{"name":"Test","id":123}`)
		var result map[string]interface{}

		err := codec.Decode(jsonData, &result)
		require.NoError(t, err)
		assert.Equal(t, "Test", result["name"])
	})

	t.Run("encode_nested_structure", func(t *testing.T) {
		data := map[string]interface{}{
			"user": map[string]interface{}{
				"name":  "John",
				"email": "john@example.com",
			},
			"items": []interface{}{
				map[string]interface{}{"id": 1},
				map[string]interface{}{"id": 2},
			},
		}

		encoded, err := codec.Encode(data)
		require.NoError(t, err)

		var decoded map[string]interface{}
		err = codec.Decode(encoded, &decoded)
		require.NoError(t, err)

		user := decoded["user"].(map[string]interface{})
		assert.Equal(t, "John", user["name"])
	})

	t.Run("encode_nil_returns_error", func(t *testing.T) {
		_, err := codec.Encode(nil)
		assert.ErrorIs(t, err, encoding.ErrNilValue)
	})

	t.Run("decode_empty_data", func(t *testing.T) {
		var result map[string]interface{}
		err := codec.Decode([]byte{}, &result)
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("content_type", func(t *testing.T) {
		assert.Equal(t, config.ContentTypeJSON, codec.ContentType())
	})

	t.Run("pretty_print", func(t *testing.T) {
		prettyCodec := encoding.NewJSONCodec(&config.JSONEncodingConfig{
			PrettyPrint: true,
		})

		data := map[string]interface{}{"key": "value"}
		encoded, err := prettyCodec.Encode(data)
		require.NoError(t, err)
		assert.Contains(t, string(encoded), "\n")
	})
}

// TestFunctional_Encoding_XML tests XML encoding/decoding.
func TestFunctional_Encoding_XML(t *testing.T) {
	t.Parallel()

	codec := encoding.NewXMLCodec()

	t.Run("encode_struct", func(t *testing.T) {
		type Person struct {
			Name  string `xml:"name"`
			Email string `xml:"email"`
		}

		data := Person{Name: "John", Email: "john@example.com"}
		encoded, err := codec.Encode(data)
		require.NoError(t, err)
		assert.Contains(t, string(encoded), "<name>John</name>")
		assert.Contains(t, string(encoded), "<email>john@example.com</email>")
	})

	t.Run("decode_struct", func(t *testing.T) {
		type Person struct {
			Name  string `xml:"name"`
			Email string `xml:"email"`
		}

		xmlData := []byte(`<Person><name>John</name><email>john@example.com</email></Person>`)
		var result Person

		err := codec.Decode(xmlData, &result)
		require.NoError(t, err)
		assert.Equal(t, "John", result.Name)
		assert.Equal(t, "john@example.com", result.Email)
	})

	t.Run("encode_nil_returns_error", func(t *testing.T) {
		_, err := codec.Encode(nil)
		assert.ErrorIs(t, err, encoding.ErrNilValue)
	})

	t.Run("decode_empty_data", func(t *testing.T) {
		var result struct{}
		err := codec.Decode([]byte{}, &result)
		require.NoError(t, err)
	})

	t.Run("content_type", func(t *testing.T) {
		assert.Equal(t, config.ContentTypeXML, codec.ContentType())
	})

	t.Run("encode_includes_xml_header", func(t *testing.T) {
		type Data struct {
			Value string `xml:"value"`
		}

		data := Data{Value: "test"}
		encoded, err := codec.Encode(data)
		require.NoError(t, err)
		assert.Contains(t, string(encoded), "<?xml version=")
	})
}

// TestFunctional_Encoding_YAML tests YAML encoding/decoding.
func TestFunctional_Encoding_YAML(t *testing.T) {
	t.Parallel()

	codec := encoding.NewYAMLCodec()

	t.Run("encode_map", func(t *testing.T) {
		data := map[string]interface{}{
			"name": "Test",
			"id":   123,
		}

		encoded, err := codec.Encode(data)
		require.NoError(t, err)
		assert.Contains(t, string(encoded), "name: Test")
	})

	t.Run("decode_map", func(t *testing.T) {
		yamlData := []byte("name: Test\nid: 123")
		var result map[string]interface{}

		err := codec.Decode(yamlData, &result)
		require.NoError(t, err)
		assert.Equal(t, "Test", result["name"])
		assert.Equal(t, 123, result["id"])
	})

	t.Run("encode_nested_structure", func(t *testing.T) {
		data := map[string]interface{}{
			"user": map[string]interface{}{
				"name":  "John",
				"email": "john@example.com",
			},
		}

		encoded, err := codec.Encode(data)
		require.NoError(t, err)

		var decoded map[string]interface{}
		err = codec.Decode(encoded, &decoded)
		require.NoError(t, err)

		user := decoded["user"].(map[string]interface{})
		assert.Equal(t, "John", user["name"])
	})

	t.Run("encode_nil_returns_error", func(t *testing.T) {
		_, err := codec.Encode(nil)
		assert.ErrorIs(t, err, encoding.ErrNilValue)
	})

	t.Run("decode_empty_data", func(t *testing.T) {
		var result map[string]interface{}
		err := codec.Decode([]byte{}, &result)
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("content_type", func(t *testing.T) {
		assert.Equal(t, config.ContentTypeYAML, codec.ContentType())
	})

	t.Run("encode_list", func(t *testing.T) {
		data := []interface{}{"item1", "item2", "item3"}
		encoded, err := codec.Encode(data)
		require.NoError(t, err)
		assert.Contains(t, string(encoded), "- item1")
	})
}

// TestFunctional_Encoding_ContentNegotiation tests content type negotiation.
func TestFunctional_Encoding_ContentNegotiation(t *testing.T) {
	t.Parallel()

	supportedTypes := []string{
		config.ContentTypeJSON,
		config.ContentTypeXML,
		config.ContentTypeYAML,
	}

	negotiator := encoding.NewNegotiator(supportedTypes)

	tests := []struct {
		name         string
		acceptHeader string
		expected     string
	}{
		{
			name:         "exact_match_json",
			acceptHeader: "application/json",
			expected:     config.ContentTypeJSON,
		},
		{
			name:         "exact_match_xml",
			acceptHeader: "application/xml",
			expected:     config.ContentTypeXML,
		},
		{
			name:         "exact_match_yaml",
			acceptHeader: "application/yaml",
			expected:     config.ContentTypeYAML,
		},
		{
			name:         "wildcard_returns_default",
			acceptHeader: "*/*",
			expected:     config.ContentTypeJSON,
		},
		{
			name:         "empty_header_returns_default",
			acceptHeader: "",
			expected:     config.ContentTypeJSON,
		},
		{
			name:         "quality_preference",
			acceptHeader: "application/xml;q=0.5, application/json;q=0.9",
			expected:     config.ContentTypeJSON,
		},
		{
			name:         "multiple_types_first_match",
			acceptHeader: "application/json, application/xml",
			expected:     config.ContentTypeJSON,
		},
		{
			name:         "unsupported_type_returns_default",
			acceptHeader: "text/html",
			expected:     config.ContentTypeJSON,
		},
		{
			name:         "partial_wildcard",
			acceptHeader: "application/*",
			expected:     config.ContentTypeJSON,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := negotiator.Negotiate(tt.acceptHeader)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestFunctional_Encoding_CodecFactory tests codec factory functionality.
func TestFunctional_Encoding_CodecFactory(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	factory := encoding.NewCodecFactory(logger)

	t.Run("get_json_codec", func(t *testing.T) {
		codec, err := factory.GetCodec(config.ContentTypeJSON)
		require.NoError(t, err)
		assert.Equal(t, config.ContentTypeJSON, codec.ContentType())
	})

	t.Run("get_xml_codec", func(t *testing.T) {
		codec, err := factory.GetCodec(config.ContentTypeXML)
		require.NoError(t, err)
		assert.Equal(t, config.ContentTypeXML, codec.ContentType())
	})

	t.Run("get_yaml_codec", func(t *testing.T) {
		codec, err := factory.GetCodec(config.ContentTypeYAML)
		require.NoError(t, err)
		assert.Equal(t, config.ContentTypeYAML, codec.ContentType())
	})

	t.Run("unsupported_content_type", func(t *testing.T) {
		_, err := factory.GetCodec("text/html")
		assert.ErrorIs(t, err, encoding.ErrUnsupportedContentType)
	})

	t.Run("content_type_with_charset", func(t *testing.T) {
		codec, err := factory.GetCodec("application/json; charset=utf-8")
		require.NoError(t, err)
		assert.Equal(t, config.ContentTypeJSON, codec.ContentType())
	})

	t.Run("supported_types", func(t *testing.T) {
		types := factory.SupportedTypes()
		assert.Contains(t, types, config.ContentTypeJSON)
		assert.Contains(t, types, config.ContentTypeXML)
		assert.Contains(t, types, config.ContentTypeYAML)
	})
}

// TestFunctional_Encoding_ConvenienceFunctions tests convenience encoding functions.
func TestFunctional_Encoding_ConvenienceFunctions(t *testing.T) {
	t.Parallel()

	t.Run("marshal_json", func(t *testing.T) {
		data := map[string]interface{}{"key": "value"}
		encoded, err := encoding.MarshalJSON(data, false)
		require.NoError(t, err)
		assert.Contains(t, string(encoded), `"key":"value"`)
	})

	t.Run("unmarshal_json", func(t *testing.T) {
		jsonData := []byte(`{"key":"value"}`)
		var result map[string]interface{}
		err := encoding.UnmarshalJSON(jsonData, &result)
		require.NoError(t, err)
		assert.Equal(t, "value", result["key"])
	})

	t.Run("json_to_map", func(t *testing.T) {
		jsonData := []byte(`{"key":"value","nested":{"inner":"data"}}`)
		result, err := encoding.JSONToMap(jsonData)
		require.NoError(t, err)
		assert.Equal(t, "value", result["key"])
		nested := result["nested"].(map[string]interface{})
		assert.Equal(t, "data", nested["inner"])
	})

	t.Run("map_to_json", func(t *testing.T) {
		data := map[string]interface{}{"key": "value"}
		encoded, err := encoding.MapToJSON(data, false)
		require.NoError(t, err)
		assert.Contains(t, string(encoded), `"key":"value"`)
	})

	t.Run("marshal_yaml", func(t *testing.T) {
		data := map[string]interface{}{"key": "value"}
		encoded, err := encoding.MarshalYAML(data)
		require.NoError(t, err)
		assert.Contains(t, string(encoded), "key: value")
	})

	t.Run("yaml_to_map", func(t *testing.T) {
		yamlData := []byte("key: value\nnested:\n  inner: data")
		result, err := encoding.YAMLToMap(yamlData)
		require.NoError(t, err)
		assert.Equal(t, "value", result["key"])
	})

	t.Run("map_to_yaml", func(t *testing.T) {
		data := map[string]interface{}{"key": "value"}
		encoded, err := encoding.MapToYAML(data)
		require.NoError(t, err)
		assert.Contains(t, string(encoded), "key: value")
	})
}

// TestFunctional_Encoding_ContentTypeToEncoding tests content type to encoding conversion.
func TestFunctional_Encoding_ContentTypeToEncoding(t *testing.T) {
	t.Parallel()

	tests := []struct {
		contentType string
		expected    string
	}{
		{config.ContentTypeJSON, config.EncodingJSON},
		{config.ContentTypeXML, config.EncodingXML},
		{config.ContentTypeYAML, config.EncodingYAML},
		{config.ContentTypeProtobuf, config.EncodingProtobuf},
		{"text/json", config.EncodingJSON},
		{"text/xml", config.EncodingXML},
		{"application/x-yaml", config.EncodingYAML},
		{"unknown/type", config.EncodingJSON}, // Default
	}

	for _, tt := range tests {
		t.Run(tt.contentType, func(t *testing.T) {
			result := encoding.ContentTypeToEncoding(tt.contentType)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestFunctional_Encoding_GetContentTypeFromConfig tests content type selection from config.
func TestFunctional_Encoding_GetContentTypeFromConfig(t *testing.T) {
	t.Parallel()

	t.Run("nil_config_returns_json", func(t *testing.T) {
		result := encoding.GetContentTypeFromConfig(nil, "")
		assert.Equal(t, config.ContentTypeJSON, result)
	})

	t.Run("negotiation_disabled_uses_response_encoding", func(t *testing.T) {
		cfg := &config.EncodingConfig{
			EnableContentNegotiation: false,
			ResponseEncoding:         config.EncodingXML,
		}
		result := encoding.GetContentTypeFromConfig(cfg, "application/json")
		assert.Equal(t, config.ContentTypeXML, result)
	})

	t.Run("negotiation_enabled_uses_accept_header", func(t *testing.T) {
		cfg := &config.EncodingConfig{
			EnableContentNegotiation: true,
			SupportedContentTypes: []string{
				config.ContentTypeJSON,
				config.ContentTypeXML,
			},
		}
		result := encoding.GetContentTypeFromConfig(cfg, "application/xml")
		assert.Equal(t, config.ContentTypeXML, result)
	})
}

// TestFunctional_Encoding_RoundTrip tests encoding/decoding round trips.
func TestFunctional_Encoding_RoundTrip(t *testing.T) {
	t.Parallel()

	testData := map[string]interface{}{
		"string":  "hello",
		"number":  42,
		"float":   3.14,
		"boolean": true,
		"null":    nil,
		"array":   []interface{}{"a", "b", "c"},
		"nested": map[string]interface{}{
			"key": "value",
		},
	}

	t.Run("json_round_trip", func(t *testing.T) {
		codec := encoding.NewJSONCodec(nil)

		encoded, err := codec.Encode(testData)
		require.NoError(t, err)

		var decoded map[string]interface{}
		err = codec.Decode(encoded, &decoded)
		require.NoError(t, err)

		assert.Equal(t, testData["string"], decoded["string"])
		assert.Equal(t, testData["boolean"], decoded["boolean"])
	})

	t.Run("yaml_round_trip", func(t *testing.T) {
		codec := encoding.NewYAMLCodec()

		encoded, err := codec.Encode(testData)
		require.NoError(t, err)

		var decoded map[string]interface{}
		err = codec.Decode(encoded, &decoded)
		require.NoError(t, err)

		assert.Equal(t, testData["string"], decoded["string"])
		assert.Equal(t, testData["boolean"], decoded["boolean"])
	})
}

// TestFunctional_Encoding_JSON_Default tests JSON encoding with default options.
func TestFunctional_Encoding_JSON_Default(t *testing.T) {
	t.Parallel()

	codec := encoding.NewJSONCodec(nil)

	tests := []struct {
		name     string
		data     interface{}
		contains []string
	}{
		{
			name: "simple_object",
			data: map[string]interface{}{
				"name": "Test",
				"id":   123,
			},
			contains: []string{`"name":"Test"`, `"id":123`},
		},
		{
			name: "nested_object",
			data: map[string]interface{}{
				"user": map[string]interface{}{
					"name": "John",
				},
			},
			contains: []string{`"user":{`, `"name":"John"`},
		},
		{
			name: "array",
			data: map[string]interface{}{
				"items": []interface{}{"a", "b", "c"},
			},
			contains: []string{`"items":["a","b","c"]`},
		},
		{
			name: "boolean_values",
			data: map[string]interface{}{
				"active":  true,
				"deleted": false,
			},
			contains: []string{`"active":true`, `"deleted":false`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := codec.Encode(tt.data)
			require.NoError(t, err)

			for _, expected := range tt.contains {
				assert.Contains(t, string(encoded), expected)
			}
		})
	}
}

// TestFunctional_Encoding_JSON_EmitDefaults tests JSON encoding with emit defaults.
func TestFunctional_Encoding_JSON_EmitDefaults(t *testing.T) {
	t.Parallel()

	// Note: EmitDefaults is primarily for protobuf messages
	// For standard Go types, we test that zero values are included
	codec := encoding.NewJSONCodec(&config.JSONEncodingConfig{
		EmitDefaults: true,
	})

	tests := []struct {
		name     string
		data     interface{}
		contains []string
	}{
		{
			name: "with_zero_values",
			data: map[string]interface{}{
				"name":   "",
				"count":  0,
				"active": false,
			},
			contains: []string{`"name":""`, `"count":0`, `"active":false`},
		},
		{
			name: "with_nil_value",
			data: map[string]interface{}{
				"name": "Test",
				"data": nil,
			},
			contains: []string{`"name":"Test"`, `"data":null`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := codec.Encode(tt.data)
			require.NoError(t, err)

			for _, expected := range tt.contains {
				assert.Contains(t, string(encoded), expected)
			}
		})
	}
}

// TestFunctional_Encoding_JSON_PrettyPrint tests JSON encoding with pretty print.
func TestFunctional_Encoding_JSON_PrettyPrint(t *testing.T) {
	t.Parallel()

	prettyCodec := encoding.NewJSONCodec(&config.JSONEncodingConfig{
		PrettyPrint: true,
	})
	compactCodec := encoding.NewJSONCodec(&config.JSONEncodingConfig{
		PrettyPrint: false,
	})

	data := map[string]interface{}{
		"name": "Test",
		"nested": map[string]interface{}{
			"key": "value",
		},
	}

	t.Run("pretty_print_contains_newlines", func(t *testing.T) {
		encoded, err := prettyCodec.Encode(data)
		require.NoError(t, err)
		assert.Contains(t, string(encoded), "\n")
		assert.Contains(t, string(encoded), "  ") // Indentation
	})

	t.Run("compact_no_newlines", func(t *testing.T) {
		encoded, err := compactCodec.Encode(data)
		require.NoError(t, err)
		assert.NotContains(t, string(encoded), "\n")
	})

	t.Run("pretty_is_longer", func(t *testing.T) {
		pretty, err := prettyCodec.Encode(data)
		require.NoError(t, err)

		compact, err := compactCodec.Encode(data)
		require.NoError(t, err)

		assert.Greater(t, len(pretty), len(compact))
	})
}

// TestFunctional_Encoding_JSON_Decode tests JSON decoding.
func TestFunctional_Encoding_JSON_Decode(t *testing.T) {
	t.Parallel()

	codec := encoding.NewJSONCodec(nil)

	tests := []struct {
		name     string
		json     string
		expected map[string]interface{}
	}{
		{
			name: "simple_object",
			json: `{"name":"Test","id":123}`,
			expected: map[string]interface{}{
				"name": "Test",
			},
		},
		{
			name: "nested_object",
			json: `{"user":{"name":"John","email":"john@example.com"}}`,
			expected: map[string]interface{}{
				"user": map[string]interface{}{
					"name":  "John",
					"email": "john@example.com",
				},
			},
		},
		{
			name: "with_array",
			json: `{"items":["a","b","c"]}`,
			expected: map[string]interface{}{
				"items": []interface{}{"a", "b", "c"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result map[string]interface{}
			err := codec.Decode([]byte(tt.json), &result)
			require.NoError(t, err)

			// Check key fields
			for key, expectedVal := range tt.expected {
				if nested, ok := expectedVal.(map[string]interface{}); ok {
					resultNested, ok := result[key].(map[string]interface{})
					require.True(t, ok)
					for nestedKey, nestedVal := range nested {
						assert.Equal(t, nestedVal, resultNested[nestedKey])
					}
				} else {
					assert.Equal(t, expectedVal, result[key])
				}
			}
		})
	}
}

// TestFunctional_Encoding_XML_Encode tests XML encoding.
func TestFunctional_Encoding_XML_Encode(t *testing.T) {
	t.Parallel()

	codec := encoding.NewXMLCodec()

	t.Run("encode_struct", func(t *testing.T) {
		type Person struct {
			Name  string `xml:"name"`
			Email string `xml:"email"`
			Age   int    `xml:"age"`
		}

		data := Person{Name: "John", Email: "john@example.com", Age: 30}
		encoded, err := codec.Encode(data)
		require.NoError(t, err)

		assert.Contains(t, string(encoded), "<name>John</name>")
		assert.Contains(t, string(encoded), "<email>john@example.com</email>")
		assert.Contains(t, string(encoded), "<age>30</age>")
	})

	t.Run("encode_with_attributes", func(t *testing.T) {
		type Item struct {
			ID   string `xml:"id,attr"`
			Name string `xml:"name"`
		}

		data := Item{ID: "123", Name: "Test Item"}
		encoded, err := codec.Encode(data)
		require.NoError(t, err)

		assert.Contains(t, string(encoded), `id="123"`)
		assert.Contains(t, string(encoded), "<name>Test Item</name>")
	})

	t.Run("encode_nested_struct", func(t *testing.T) {
		type Address struct {
			City string `xml:"city"`
		}
		type Person struct {
			Name    string  `xml:"name"`
			Address Address `xml:"address"`
		}

		data := Person{Name: "John", Address: Address{City: "NYC"}}
		encoded, err := codec.Encode(data)
		require.NoError(t, err)

		assert.Contains(t, string(encoded), "<name>John</name>")
		assert.Contains(t, string(encoded), "<city>NYC</city>")
	})
}

// TestFunctional_Encoding_XML_Decode tests XML decoding.
func TestFunctional_Encoding_XML_Decode(t *testing.T) {
	t.Parallel()

	codec := encoding.NewXMLCodec()

	t.Run("decode_simple_struct", func(t *testing.T) {
		type Person struct {
			Name  string `xml:"name"`
			Email string `xml:"email"`
		}

		xmlData := []byte(`<Person><name>John</name><email>john@example.com</email></Person>`)
		var result Person

		err := codec.Decode(xmlData, &result)
		require.NoError(t, err)
		assert.Equal(t, "John", result.Name)
		assert.Equal(t, "john@example.com", result.Email)
	})

	t.Run("decode_with_attributes", func(t *testing.T) {
		type Item struct {
			ID   string `xml:"id,attr"`
			Name string `xml:"name"`
		}

		xmlData := []byte(`<Item id="123"><name>Test</name></Item>`)
		var result Item

		err := codec.Decode(xmlData, &result)
		require.NoError(t, err)
		assert.Equal(t, "123", result.ID)
		assert.Equal(t, "Test", result.Name)
	})

	t.Run("decode_nested_struct", func(t *testing.T) {
		type Address struct {
			City string `xml:"city"`
		}
		type Person struct {
			Name    string  `xml:"name"`
			Address Address `xml:"address"`
		}

		xmlData := []byte(`<Person><name>John</name><address><city>NYC</city></address></Person>`)
		var result Person

		err := codec.Decode(xmlData, &result)
		require.NoError(t, err)
		assert.Equal(t, "John", result.Name)
		assert.Equal(t, "NYC", result.Address.City)
	})
}

// TestFunctional_Encoding_YAML_Encode tests YAML encoding.
func TestFunctional_Encoding_YAML_Encode(t *testing.T) {
	t.Parallel()

	codec := encoding.NewYAMLCodec()

	tests := []struct {
		name     string
		data     interface{}
		contains []string
	}{
		{
			name: "simple_map",
			data: map[string]interface{}{
				"name": "Test",
				"id":   123,
			},
			contains: []string{"name: Test"},
		},
		{
			name: "nested_map",
			data: map[string]interface{}{
				"user": map[string]interface{}{
					"name": "John",
				},
			},
			contains: []string{"user:", "name: John"},
		},
		{
			name:     "list",
			data:     []interface{}{"item1", "item2", "item3"},
			contains: []string{"- item1", "- item2", "- item3"},
		},
		{
			name: "map_with_list",
			data: map[string]interface{}{
				"items": []interface{}{"a", "b", "c"},
			},
			contains: []string{"items:", "- a", "- b", "- c"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := codec.Encode(tt.data)
			require.NoError(t, err)

			for _, expected := range tt.contains {
				assert.Contains(t, string(encoded), expected)
			}
		})
	}
}

// TestFunctional_Encoding_YAML_Decode tests YAML decoding.
func TestFunctional_Encoding_YAML_Decode(t *testing.T) {
	t.Parallel()

	codec := encoding.NewYAMLCodec()

	tests := []struct {
		name     string
		yaml     string
		expected map[string]interface{}
	}{
		{
			name: "simple_map",
			yaml: "name: Test\nid: 123",
			expected: map[string]interface{}{
				"name": "Test",
				"id":   123,
			},
		},
		{
			name: "nested_map",
			yaml: "user:\n  name: John\n  email: john@example.com",
			expected: map[string]interface{}{
				"user": map[string]interface{}{
					"name":  "John",
					"email": "john@example.com",
				},
			},
		},
		{
			name: "with_list",
			yaml: "items:\n  - a\n  - b\n  - c",
			expected: map[string]interface{}{
				"items": []interface{}{"a", "b", "c"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result map[string]interface{}
			err := codec.Decode([]byte(tt.yaml), &result)
			require.NoError(t, err)

			for key, expectedVal := range tt.expected {
				if nested, ok := expectedVal.(map[string]interface{}); ok {
					resultNested, ok := result[key].(map[string]interface{})
					require.True(t, ok)
					for nestedKey, nestedVal := range nested {
						assert.Equal(t, nestedVal, resultNested[nestedKey])
					}
				} else {
					assert.Equal(t, expectedVal, result[key])
				}
			}
		})
	}
}

// TestFunctional_Encoding_ContentNegotiation_Accept tests content negotiation with Accept header.
func TestFunctional_Encoding_ContentNegotiation_Accept(t *testing.T) {
	t.Parallel()

	supportedTypes := []string{
		config.ContentTypeJSON,
		config.ContentTypeXML,
		config.ContentTypeYAML,
	}

	negotiator := encoding.NewNegotiator(supportedTypes)

	tests := []struct {
		name         string
		acceptHeader string
		expected     string
	}{
		{
			name:         "accept_json",
			acceptHeader: "application/json",
			expected:     config.ContentTypeJSON,
		},
		{
			name:         "accept_xml",
			acceptHeader: "application/xml",
			expected:     config.ContentTypeXML,
		},
		{
			name:         "accept_yaml",
			acceptHeader: "application/yaml",
			expected:     config.ContentTypeYAML,
		},
		{
			name:         "accept_text_json",
			acceptHeader: "text/json",
			expected:     config.ContentTypeJSON, // Falls back to default
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := negotiator.Negotiate(tt.acceptHeader)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestFunctional_Encoding_ContentNegotiation_Quality tests content negotiation with quality values.
func TestFunctional_Encoding_ContentNegotiation_Quality(t *testing.T) {
	t.Parallel()

	supportedTypes := []string{
		config.ContentTypeJSON,
		config.ContentTypeXML,
		config.ContentTypeYAML,
	}

	negotiator := encoding.NewNegotiator(supportedTypes)

	tests := []struct {
		name         string
		acceptHeader string
		expected     string
	}{
		{
			name:         "json_higher_quality",
			acceptHeader: "application/xml;q=0.5, application/json;q=0.9",
			expected:     config.ContentTypeJSON,
		},
		{
			name:         "xml_higher_quality",
			acceptHeader: "application/json;q=0.5, application/xml;q=0.9",
			expected:     config.ContentTypeXML,
		},
		{
			name:         "equal_quality_first_wins",
			acceptHeader: "application/json;q=0.9, application/xml;q=0.9",
			expected:     config.ContentTypeJSON,
		},
		{
			name:         "default_quality_is_1",
			acceptHeader: "application/xml;q=0.5, application/json",
			expected:     config.ContentTypeJSON,
		},
		{
			name:         "multiple_with_varying_quality",
			acceptHeader: "application/yaml;q=0.3, application/xml;q=0.5, application/json;q=0.9",
			expected:     config.ContentTypeJSON,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := negotiator.Negotiate(tt.acceptHeader)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestFunctional_Encoding_ContentNegotiation_Fallback tests content negotiation fallback.
func TestFunctional_Encoding_ContentNegotiation_Fallback(t *testing.T) {
	t.Parallel()

	supportedTypes := []string{
		config.ContentTypeJSON,
		config.ContentTypeXML,
	}

	negotiator := encoding.NewNegotiator(supportedTypes)

	tests := []struct {
		name         string
		acceptHeader string
		expected     string
	}{
		{
			name:         "empty_header_returns_default",
			acceptHeader: "",
			expected:     config.ContentTypeJSON,
		},
		{
			name:         "unsupported_type_returns_default",
			acceptHeader: "text/html",
			expected:     config.ContentTypeJSON,
		},
		{
			name:         "wildcard_returns_first_supported",
			acceptHeader: "*/*",
			expected:     config.ContentTypeJSON,
		},
		{
			name:         "partial_wildcard_matches",
			acceptHeader: "application/*",
			expected:     config.ContentTypeJSON,
		},
		{
			name:         "unsupported_with_wildcard_fallback",
			acceptHeader: "text/html, */*;q=0.1",
			expected:     config.ContentTypeJSON,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := negotiator.Negotiate(tt.acceptHeader)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestFunctional_Encoding_NegotiatorWithDefault tests negotiator with custom default.
func TestFunctional_Encoding_NegotiatorWithDefault(t *testing.T) {
	t.Parallel()

	supportedTypes := []string{
		config.ContentTypeJSON,
		config.ContentTypeXML,
	}

	negotiator := encoding.NewNegotiator(
		supportedTypes,
		encoding.WithDefaultType(config.ContentTypeXML),
	)

	t.Run("empty_header_returns_custom_default", func(t *testing.T) {
		result := negotiator.Negotiate("")
		assert.Equal(t, config.ContentTypeXML, result)
	})

	t.Run("unsupported_returns_custom_default", func(t *testing.T) {
		result := negotiator.Negotiate("text/html")
		assert.Equal(t, config.ContentTypeXML, result)
	})
}
