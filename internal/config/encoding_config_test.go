// Package config provides configuration types and loading for the API Gateway.
package config

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestEncodingConfig_IsEmpty(t *testing.T) {
	tests := []struct {
		name     string
		config   *EncodingConfig
		expected bool
	}{
		{
			name:     "nil config",
			config:   nil,
			expected: true,
		},
		{
			name:     "empty config",
			config:   &EncodingConfig{},
			expected: true,
		},
		{
			name: "config with request encoding",
			config: &EncodingConfig{
				RequestEncoding: EncodingJSON,
			},
			expected: false,
		},
		{
			name: "config with response encoding",
			config: &EncodingConfig{
				ResponseEncoding: EncodingXML,
			},
			expected: false,
		},
		{
			name: "config with content negotiation",
			config: &EncodingConfig{
				EnableContentNegotiation: true,
			},
			expected: false,
		},
		{
			name: "config with supported content types",
			config: &EncodingConfig{
				SupportedContentTypes: []string{ContentTypeJSON, ContentTypeXML},
			},
			expected: false,
		},
		{
			name: "config with JSON options",
			config: &EncodingConfig{
				JSON: &JSONEncodingConfig{
					PrettyPrint: true,
				},
			},
			expected: false,
		},
		{
			name: "config with protobuf options",
			config: &EncodingConfig{
				Protobuf: &ProtobufEncodingConfig{
					UseJSONEncoding: true,
				},
			},
			expected: false,
		},
		{
			name: "config with compression",
			config: &EncodingConfig{
				Compression: &CompressionConfig{
					Enabled: true,
				},
			},
			expected: false,
		},
		{
			name: "config with passthrough",
			config: &EncodingConfig{
				Passthrough: true,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.IsEmpty()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestJSONEncodingConfig_IsEmpty(t *testing.T) {
	tests := []struct {
		name     string
		config   *JSONEncodingConfig
		expected bool
	}{
		{
			name:     "nil config",
			config:   nil,
			expected: true,
		},
		{
			name:     "empty config",
			config:   &JSONEncodingConfig{},
			expected: true,
		},
		{
			name: "config with emit defaults",
			config: &JSONEncodingConfig{
				EmitDefaults: true,
			},
			expected: false,
		},
		{
			name: "config with use proto names",
			config: &JSONEncodingConfig{
				UseProtoNames: true,
			},
			expected: false,
		},
		{
			name: "config with enum as integers",
			config: &JSONEncodingConfig{
				EnumAsIntegers: true,
			},
			expected: false,
		},
		{
			name: "config with int64 as strings",
			config: &JSONEncodingConfig{
				Int64AsStrings: true,
			},
			expected: false,
		},
		{
			name: "config with pretty print",
			config: &JSONEncodingConfig{
				PrettyPrint: true,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.IsEmpty()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestProtobufEncodingConfig_IsEmpty(t *testing.T) {
	tests := []struct {
		name     string
		config   *ProtobufEncodingConfig
		expected bool
	}{
		{
			name:     "nil config",
			config:   nil,
			expected: true,
		},
		{
			name:     "empty config",
			config:   &ProtobufEncodingConfig{},
			expected: true,
		},
		{
			name: "config with use JSON encoding",
			config: &ProtobufEncodingConfig{
				UseJSONEncoding: true,
			},
			expected: false,
		},
		{
			name: "config with descriptor source",
			config: &ProtobufEncodingConfig{
				DescriptorSource: DescriptorSourceReflection,
			},
			expected: false,
		},
		{
			name: "config with descriptor file",
			config: &ProtobufEncodingConfig{
				DescriptorFile: "/path/to/descriptor.pb",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.IsEmpty()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCompressionConfig_IsEmpty(t *testing.T) {
	tests := []struct {
		name     string
		config   *CompressionConfig
		expected bool
	}{
		{
			name:     "nil config",
			config:   nil,
			expected: true,
		},
		{
			name:     "empty config",
			config:   &CompressionConfig{},
			expected: true,
		},
		{
			name: "disabled config",
			config: &CompressionConfig{
				Enabled:    false,
				Algorithms: []string{CompressionGzip},
			},
			expected: true,
		},
		{
			name: "enabled config",
			config: &CompressionConfig{
				Enabled: true,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.IsEmpty()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDefaultEncodingConfig(t *testing.T) {
	config := DefaultEncodingConfig()

	assert.NotNil(t, config)
	assert.Equal(t, EncodingJSON, config.RequestEncoding)
	assert.Equal(t, EncodingJSON, config.ResponseEncoding)
	assert.True(t, config.EnableContentNegotiation)
	assert.Contains(t, config.SupportedContentTypes, ContentTypeJSON)
	assert.Contains(t, config.SupportedContentTypes, ContentTypeXML)

	// Verify JSON config
	assert.NotNil(t, config.JSON)
	assert.False(t, config.JSON.EmitDefaults)
	assert.False(t, config.JSON.PrettyPrint)

	// Verify compression config
	assert.NotNil(t, config.Compression)
	assert.True(t, config.Compression.Enabled)
	assert.Contains(t, config.Compression.Algorithms, CompressionGzip)
	assert.Equal(t, 1024, config.Compression.MinSize)
	assert.Equal(t, 6, config.Compression.Level)
}

func TestEncodingTypeConstants(t *testing.T) {
	assert.Equal(t, "json", EncodingJSON)
	assert.Equal(t, "xml", EncodingXML)
	assert.Equal(t, "yaml", EncodingYAML)
	assert.Equal(t, "protobuf", EncodingProtobuf)
}

func TestCompressionAlgorithmConstants(t *testing.T) {
	assert.Equal(t, "gzip", CompressionGzip)
	assert.Equal(t, "deflate", CompressionDeflate)
	assert.Equal(t, "snappy", CompressionSnappy)
	assert.Equal(t, "zstd", CompressionZstd)
}

func TestDescriptorSourceConstants(t *testing.T) {
	assert.Equal(t, "reflection", DescriptorSourceReflection)
	assert.Equal(t, "file", DescriptorSourceFile)
}

func TestContentTypeConstants(t *testing.T) {
	assert.Equal(t, "application/json", ContentTypeJSON)
	assert.Equal(t, "application/xml", ContentTypeXML)
	assert.Equal(t, "application/yaml", ContentTypeYAML)
	assert.Equal(t, "application/protobuf", ContentTypeProtobuf)
	assert.Equal(t, "application/grpc", ContentTypeGRPC)
	assert.Equal(t, "application/octet-stream", ContentTypeOctetStream)
}

func TestEncodingConfig_YAMLMarshalUnmarshal(t *testing.T) {
	original := &EncodingConfig{
		RequestEncoding:          EncodingJSON,
		ResponseEncoding:         EncodingJSON,
		EnableContentNegotiation: true,
		SupportedContentTypes:    []string{ContentTypeJSON, ContentTypeXML, ContentTypeYAML},
		JSON: &JSONEncodingConfig{
			EmitDefaults:   true,
			UseProtoNames:  false,
			EnumAsIntegers: true,
			Int64AsStrings: true,
			PrettyPrint:    true,
		},
		Protobuf: &ProtobufEncodingConfig{
			UseJSONEncoding:  true,
			DescriptorSource: DescriptorSourceReflection,
		},
		Compression: &CompressionConfig{
			Enabled:    true,
			Algorithms: []string{CompressionGzip, CompressionZstd},
			MinSize:    2048,
			Level:      9,
		},
		Passthrough: false,
	}

	// Marshal to YAML
	data, err := yaml.Marshal(original)
	require.NoError(t, err)

	// Unmarshal back
	var result EncodingConfig
	err = yaml.Unmarshal(data, &result)
	require.NoError(t, err)

	// Verify
	assert.Equal(t, original.RequestEncoding, result.RequestEncoding)
	assert.Equal(t, original.ResponseEncoding, result.ResponseEncoding)
	assert.Equal(t, original.EnableContentNegotiation, result.EnableContentNegotiation)
	assert.Equal(t, original.SupportedContentTypes, result.SupportedContentTypes)
	assert.Equal(t, original.Passthrough, result.Passthrough)

	// Verify JSON config
	assert.NotNil(t, result.JSON)
	assert.Equal(t, original.JSON.EmitDefaults, result.JSON.EmitDefaults)
	assert.Equal(t, original.JSON.UseProtoNames, result.JSON.UseProtoNames)
	assert.Equal(t, original.JSON.EnumAsIntegers, result.JSON.EnumAsIntegers)
	assert.Equal(t, original.JSON.Int64AsStrings, result.JSON.Int64AsStrings)
	assert.Equal(t, original.JSON.PrettyPrint, result.JSON.PrettyPrint)

	// Verify Protobuf config
	assert.NotNil(t, result.Protobuf)
	assert.Equal(t, original.Protobuf.UseJSONEncoding, result.Protobuf.UseJSONEncoding)
	assert.Equal(t, original.Protobuf.DescriptorSource, result.Protobuf.DescriptorSource)

	// Verify Compression config
	assert.NotNil(t, result.Compression)
	assert.Equal(t, original.Compression.Enabled, result.Compression.Enabled)
	assert.Equal(t, original.Compression.Algorithms, result.Compression.Algorithms)
	assert.Equal(t, original.Compression.MinSize, result.Compression.MinSize)
	assert.Equal(t, original.Compression.Level, result.Compression.Level)
}

func TestEncodingConfig_JSONMarshalUnmarshal(t *testing.T) {
	original := &EncodingConfig{
		RequestEncoding:          EncodingJSON,
		ResponseEncoding:         EncodingXML,
		EnableContentNegotiation: true,
		SupportedContentTypes:    []string{ContentTypeJSON, ContentTypeXML},
		JSON: &JSONEncodingConfig{
			PrettyPrint: true,
		},
		Compression: &CompressionConfig{
			Enabled:    true,
			Algorithms: []string{CompressionGzip},
			MinSize:    1024,
			Level:      6,
		},
	}

	// Marshal to JSON
	data, err := json.Marshal(original)
	require.NoError(t, err)

	// Unmarshal back
	var result EncodingConfig
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	// Verify
	assert.Equal(t, original.RequestEncoding, result.RequestEncoding)
	assert.Equal(t, original.ResponseEncoding, result.ResponseEncoding)
	assert.Equal(t, original.EnableContentNegotiation, result.EnableContentNegotiation)
	assert.Equal(t, original.SupportedContentTypes, result.SupportedContentTypes)
	assert.NotNil(t, result.JSON)
	assert.Equal(t, original.JSON.PrettyPrint, result.JSON.PrettyPrint)
	assert.NotNil(t, result.Compression)
	assert.Equal(t, original.Compression.Enabled, result.Compression.Enabled)
}

func TestJSONEncodingConfig_Struct(t *testing.T) {
	config := JSONEncodingConfig{
		EmitDefaults:   true,
		UseProtoNames:  true,
		EnumAsIntegers: true,
		Int64AsStrings: true,
		PrettyPrint:    true,
	}

	assert.True(t, config.EmitDefaults)
	assert.True(t, config.UseProtoNames)
	assert.True(t, config.EnumAsIntegers)
	assert.True(t, config.Int64AsStrings)
	assert.True(t, config.PrettyPrint)
}

func TestProtobufEncodingConfig_Struct(t *testing.T) {
	config := ProtobufEncodingConfig{
		UseJSONEncoding:  true,
		DescriptorSource: DescriptorSourceFile,
		DescriptorFile:   "/path/to/descriptor.pb",
	}

	assert.True(t, config.UseJSONEncoding)
	assert.Equal(t, DescriptorSourceFile, config.DescriptorSource)
	assert.Equal(t, "/path/to/descriptor.pb", config.DescriptorFile)
}

func TestCompressionConfig_Struct(t *testing.T) {
	config := CompressionConfig{
		Enabled:    true,
		Algorithms: []string{CompressionGzip, CompressionDeflate, CompressionZstd},
		MinSize:    4096,
		Level:      9,
	}

	assert.True(t, config.Enabled)
	assert.Len(t, config.Algorithms, 3)
	assert.Contains(t, config.Algorithms, CompressionGzip)
	assert.Contains(t, config.Algorithms, CompressionDeflate)
	assert.Contains(t, config.Algorithms, CompressionZstd)
	assert.Equal(t, 4096, config.MinSize)
	assert.Equal(t, 9, config.Level)
}

func TestEncodingConfig_FullConfiguration(t *testing.T) {
	config := &EncodingConfig{
		RequestEncoding:          EncodingJSON,
		ResponseEncoding:         EncodingJSON,
		EnableContentNegotiation: true,
		SupportedContentTypes:    []string{ContentTypeJSON, ContentTypeXML, ContentTypeYAML},
		JSON: &JSONEncodingConfig{
			EmitDefaults:   true,
			UseProtoNames:  false,
			EnumAsIntegers: false,
			Int64AsStrings: true,
			PrettyPrint:    false,
		},
		Protobuf: &ProtobufEncodingConfig{
			UseJSONEncoding:  true,
			DescriptorSource: DescriptorSourceReflection,
		},
		Compression: &CompressionConfig{
			Enabled:    true,
			Algorithms: []string{CompressionGzip, CompressionZstd},
			MinSize:    1024,
			Level:      6,
		},
		Passthrough: false,
	}

	assert.False(t, config.IsEmpty())
	assert.False(t, config.JSON.IsEmpty())
	assert.False(t, config.Protobuf.IsEmpty())
	assert.False(t, config.Compression.IsEmpty())
}

// ---------------------------------------------------------------------------
// Tests for contentTypeToEncoding helper
// ---------------------------------------------------------------------------

func TestContentTypeToEncoding(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		expected    string
	}{
		{
			name:        "application/json",
			contentType: "application/json",
			expected:    "json",
		},
		{
			name:        "text/json",
			contentType: "text/json",
			expected:    "json",
		},
		{
			name:        "application/json with charset",
			contentType: "application/json; charset=utf-8",
			expected:    "json",
		},
		{
			name:        "application/xml",
			contentType: "application/xml",
			expected:    "xml",
		},
		{
			name:        "text/xml",
			contentType: "text/xml",
			expected:    "xml",
		},
		{
			name:        "application/yaml",
			contentType: "application/yaml",
			expected:    "yaml",
		},
		{
			name:        "application/x-yaml",
			contentType: "application/x-yaml",
			expected:    "yaml",
		},
		{
			name:        "text/yaml",
			contentType: "text/yaml",
			expected:    "yaml",
		},
		{
			name:        "application/protobuf",
			contentType: "application/protobuf",
			expected:    "protobuf",
		},
		{
			name:        "application/x-protobuf",
			contentType: "application/x-protobuf",
			expected:    "protobuf",
		},
		{
			name:        "unknown type returned as-is",
			contentType: "unknown/type",
			expected:    "unknown/type",
		},
		{
			name:        "empty string",
			contentType: "",
			expected:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := contentTypeToEncoding(tt.contentType)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ---------------------------------------------------------------------------
// Tests for canonicalContentType helper
// ---------------------------------------------------------------------------

func TestCanonicalContentType(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "strips charset parameter",
			input:    "application/json; charset=utf-8",
			expected: "application/json",
		},
		{
			name:     "no parameters unchanged",
			input:    "application/json",
			expected: "application/json",
		},
		{
			name:     "strips charset with extra spaces",
			input:    "text/xml ; charset=iso-8859-1",
			expected: "text/xml",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := canonicalContentType(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ---------------------------------------------------------------------------
// Tests for UnmarshalJSON — CRD format
// ---------------------------------------------------------------------------

func TestEncodingConfig_UnmarshalJSON_CRDFormat(t *testing.T) {
	tests := []struct {
		name                        string
		jsonInput                   string
		expectedRequestEncoding     string
		expectedResponseEncoding    string
		expectedContentNegotiation  bool
		expectedSupportedCTContains []string
		expectedIsEmpty             bool
	}{
		{
			name:                        "CRD with both request and response content types",
			jsonInput:                   `{"request":{"contentType":"application/json"},"response":{"contentType":"application/xml"}}`,
			expectedRequestEncoding:     "json",
			expectedResponseEncoding:    "xml",
			expectedContentNegotiation:  true,
			expectedSupportedCTContains: []string{"application/json", "application/xml"},
			expectedIsEmpty:             false,
		},
		{
			name:                        "CRD with only request content type",
			jsonInput:                   `{"request":{"contentType":"application/json"}}`,
			expectedRequestEncoding:     "json",
			expectedResponseEncoding:    "",
			expectedContentNegotiation:  true,
			expectedSupportedCTContains: []string{"application/json"},
			expectedIsEmpty:             false,
		},
		{
			name:                        "CRD with only response content type",
			jsonInput:                   `{"response":{"contentType":"application/xml"}}`,
			expectedRequestEncoding:     "",
			expectedResponseEncoding:    "xml",
			expectedContentNegotiation:  true,
			expectedSupportedCTContains: []string{"application/xml"},
			expectedIsEmpty:             false,
		},
		{
			name:                        "CRD with different content types request=json response=xml",
			jsonInput:                   `{"request":{"contentType":"application/json"},"response":{"contentType":"application/xml"}}`,
			expectedRequestEncoding:     "json",
			expectedResponseEncoding:    "xml",
			expectedContentNegotiation:  true,
			expectedSupportedCTContains: []string{"application/json", "application/xml"},
			expectedIsEmpty:             false,
		},
		{
			name:                        "CRD with yaml content types",
			jsonInput:                   `{"request":{"contentType":"application/yaml"},"response":{"contentType":"text/yaml"}}`,
			expectedRequestEncoding:     "yaml",
			expectedResponseEncoding:    "yaml",
			expectedContentNegotiation:  true,
			expectedSupportedCTContains: []string{"application/yaml", "text/yaml"},
			expectedIsEmpty:             false,
		},
		{
			name:                        "CRD with protobuf content types",
			jsonInput:                   `{"request":{"contentType":"application/protobuf"},"response":{"contentType":"application/x-protobuf"}}`,
			expectedRequestEncoding:     "protobuf",
			expectedResponseEncoding:    "protobuf",
			expectedContentNegotiation:  true,
			expectedSupportedCTContains: []string{"application/protobuf", "application/x-protobuf"},
			expectedIsEmpty:             false,
		},
		{
			name:                        "CRD with charset in content type",
			jsonInput:                   `{"request":{"contentType":"application/json; charset=utf-8"},"response":{"contentType":"application/json"}}`,
			expectedRequestEncoding:     "json",
			expectedResponseEncoding:    "json",
			expectedContentNegotiation:  true,
			expectedSupportedCTContains: []string{"application/json"},
			expectedIsEmpty:             false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			var ec EncodingConfig

			// Act
			err := json.Unmarshal([]byte(tt.jsonInput), &ec)

			// Assert
			require.NoError(t, err)
			assert.Equal(t, tt.expectedRequestEncoding, ec.RequestEncoding)
			assert.Equal(t, tt.expectedResponseEncoding, ec.ResponseEncoding)
			assert.Equal(t, tt.expectedContentNegotiation, ec.EnableContentNegotiation)
			for _, ct := range tt.expectedSupportedCTContains {
				assert.Contains(t, ec.SupportedContentTypes, ct)
			}
			assert.Equal(t, tt.expectedIsEmpty, ec.IsEmpty())
		})
	}
}

// ---------------------------------------------------------------------------
// Tests for UnmarshalJSON — internal (backward-compatible) format
// ---------------------------------------------------------------------------

func TestEncodingConfig_UnmarshalJSON_InternalFormat(t *testing.T) {
	tests := []struct {
		name                       string
		jsonInput                  string
		expectedRequestEncoding    string
		expectedResponseEncoding   string
		expectedContentNegotiation bool
	}{
		{
			name:                       "internal format with requestEncoding and responseEncoding",
			jsonInput:                  `{"requestEncoding":"json","responseEncoding":"xml"}`,
			expectedRequestEncoding:    "json",
			expectedResponseEncoding:   "xml",
			expectedContentNegotiation: false,
		},
		{
			name:                       "internal format with all fields populated",
			jsonInput:                  `{"requestEncoding":"yaml","responseEncoding":"protobuf","enableContentNegotiation":true,"supportedContentTypes":["application/yaml","application/protobuf"]}`,
			expectedRequestEncoding:    "yaml",
			expectedResponseEncoding:   "protobuf",
			expectedContentNegotiation: true,
		},
		{
			name:                       "internal format takes precedence over CRD fields",
			jsonInput:                  `{"requestEncoding":"xml","responseEncoding":"yaml","request":{"contentType":"application/json"},"response":{"contentType":"application/json"}}`,
			expectedRequestEncoding:    "xml",
			expectedResponseEncoding:   "yaml",
			expectedContentNegotiation: false,
		},
		{
			name:                       "internal format with only requestEncoding",
			jsonInput:                  `{"requestEncoding":"json"}`,
			expectedRequestEncoding:    "json",
			expectedResponseEncoding:   "",
			expectedContentNegotiation: false,
		},
		{
			name:                       "internal format with only responseEncoding",
			jsonInput:                  `{"responseEncoding":"xml"}`,
			expectedRequestEncoding:    "",
			expectedResponseEncoding:   "xml",
			expectedContentNegotiation: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			var ec EncodingConfig

			// Act
			err := json.Unmarshal([]byte(tt.jsonInput), &ec)

			// Assert
			require.NoError(t, err)
			assert.Equal(t, tt.expectedRequestEncoding, ec.RequestEncoding)
			assert.Equal(t, tt.expectedResponseEncoding, ec.ResponseEncoding)
			assert.Equal(t, tt.expectedContentNegotiation, ec.EnableContentNegotiation)
		})
	}
}

// ---------------------------------------------------------------------------
// Tests for UnmarshalJSON — empty and nil edge cases
// ---------------------------------------------------------------------------

func TestEncodingConfig_UnmarshalJSON_EmptyAndNil(t *testing.T) {
	tests := []struct {
		name            string
		jsonInput       string
		expectedIsEmpty bool
		expectedReqEnc  string
		expectedRespEnc string
	}{
		{
			name:            "empty JSON object",
			jsonInput:       `{}`,
			expectedIsEmpty: true,
			expectedReqEnc:  "",
			expectedRespEnc: "",
		},
		{
			name:            "request with empty contentType enables negotiation but no encoding",
			jsonInput:       `{"request":{}}`,
			expectedIsEmpty: false, // EnableContentNegotiation is set to true by applyCRDEncoding
			expectedReqEnc:  "",
			expectedRespEnc: "",
		},
		{
			name:            "request with empty string contentType enables negotiation but no encoding",
			jsonInput:       `{"request":{"contentType":""}}`,
			expectedIsEmpty: false, // EnableContentNegotiation is set to true by applyCRDEncoding
			expectedReqEnc:  "",
			expectedRespEnc: "",
		},
		{
			name:            "request null",
			jsonInput:       `{"request":null}`,
			expectedIsEmpty: true,
			expectedReqEnc:  "",
			expectedRespEnc: "",
		},
		{
			name:            "response null",
			jsonInput:       `{"response":null}`,
			expectedIsEmpty: true,
			expectedReqEnc:  "",
			expectedRespEnc: "",
		},
		{
			name:            "both request and response null",
			jsonInput:       `{"request":null,"response":null}`,
			expectedIsEmpty: true,
			expectedReqEnc:  "",
			expectedRespEnc: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			var ec EncodingConfig

			// Act
			err := json.Unmarshal([]byte(tt.jsonInput), &ec)

			// Assert
			require.NoError(t, err)
			assert.Equal(t, tt.expectedIsEmpty, ec.IsEmpty())
			assert.Equal(t, tt.expectedReqEnc, ec.RequestEncoding)
			assert.Equal(t, tt.expectedRespEnc, ec.ResponseEncoding)
		})
	}
}

// ---------------------------------------------------------------------------
// Tests for UnmarshalJSON — mixed CRD + internal fields
// ---------------------------------------------------------------------------

func TestEncodingConfig_UnmarshalJSON_MixedFormat(t *testing.T) {
	t.Run("CRD format with additional json config", func(t *testing.T) {
		// Arrange
		input := `{"request":{"contentType":"application/json"},"json":{"prettyPrint":true}}`

		// Act
		var ec EncodingConfig
		err := json.Unmarshal([]byte(input), &ec)

		// Assert
		require.NoError(t, err)
		assert.Equal(t, "json", ec.RequestEncoding)
		assert.True(t, ec.EnableContentNegotiation)
		assert.NotNil(t, ec.JSON)
		assert.True(t, ec.JSON.PrettyPrint)
	})

	t.Run("CRD format with compression config", func(t *testing.T) {
		// Arrange
		input := `{"request":{"contentType":"application/json"},"response":{"contentType":"application/json"},"compression":{"enabled":true,"algorithms":["gzip"],"minSize":2048}}`

		// Act
		var ec EncodingConfig
		err := json.Unmarshal([]byte(input), &ec)

		// Assert
		require.NoError(t, err)
		assert.Equal(t, "json", ec.RequestEncoding)
		assert.Equal(t, "json", ec.ResponseEncoding)
		assert.True(t, ec.EnableContentNegotiation)
		require.NotNil(t, ec.Compression)
		assert.True(t, ec.Compression.Enabled)
		assert.Contains(t, ec.Compression.Algorithms, "gzip")
		assert.Equal(t, 2048, ec.Compression.MinSize)
	})

	t.Run("CRD format with passthrough true", func(t *testing.T) {
		// Arrange
		input := `{"request":{"contentType":"application/json"},"passthrough":true}`

		// Act
		var ec EncodingConfig
		err := json.Unmarshal([]byte(input), &ec)

		// Assert
		require.NoError(t, err)
		assert.Equal(t, "json", ec.RequestEncoding)
		assert.True(t, ec.Passthrough)
		assert.True(t, ec.EnableContentNegotiation)
	})

	t.Run("CRD format with protobuf config", func(t *testing.T) {
		// Arrange
		input := `{"request":{"contentType":"application/protobuf"},"protobuf":{"useJSONEncoding":true,"descriptorSource":"reflection"}}`

		// Act
		var ec EncodingConfig
		err := json.Unmarshal([]byte(input), &ec)

		// Assert
		require.NoError(t, err)
		assert.Equal(t, "protobuf", ec.RequestEncoding)
		assert.True(t, ec.EnableContentNegotiation)
		require.NotNil(t, ec.Protobuf)
		assert.True(t, ec.Protobuf.UseJSONEncoding)
		assert.Equal(t, "reflection", ec.Protobuf.DescriptorSource)
	})
}

// ---------------------------------------------------------------------------
// Tests for UnmarshalJSON — SupportedContentTypes deduplication
// ---------------------------------------------------------------------------

func TestEncodingConfig_UnmarshalJSON_SupportedContentTypes_Dedup(t *testing.T) {
	t.Run("same content type for request and response does not duplicate", func(t *testing.T) {
		// Arrange
		input := `{"request":{"contentType":"application/json"},"response":{"contentType":"application/json"}}`

		// Act
		var ec EncodingConfig
		err := json.Unmarshal([]byte(input), &ec)

		// Assert
		require.NoError(t, err)
		assert.Equal(t, "json", ec.RequestEncoding)
		assert.Equal(t, "json", ec.ResponseEncoding)
		// SupportedContentTypes should contain "application/json" exactly once
		count := 0
		for _, ct := range ec.SupportedContentTypes {
			if ct == "application/json" {
				count++
			}
		}
		assert.Equal(t, 1, count, "application/json should appear exactly once in SupportedContentTypes")
	})

	t.Run("existing supportedContentTypes are preserved and not duplicated", func(t *testing.T) {
		// Arrange — use internal format with pre-existing SupportedContentTypes,
		// then verify CRD path doesn't run (since requestEncoding is set).
		input := `{"requestEncoding":"json","supportedContentTypes":["application/json","application/xml"]}`

		// Act
		var ec EncodingConfig
		err := json.Unmarshal([]byte(input), &ec)

		// Assert
		require.NoError(t, err)
		assert.Equal(t, []string{"application/json", "application/xml"}, ec.SupportedContentTypes)
	})

	t.Run("different content types for request and response both appear", func(t *testing.T) {
		// Arrange
		input := `{"request":{"contentType":"application/json"},"response":{"contentType":"application/xml"}}`

		// Act
		var ec EncodingConfig
		err := json.Unmarshal([]byte(input), &ec)

		// Assert
		require.NoError(t, err)
		assert.Len(t, ec.SupportedContentTypes, 2)
		assert.Contains(t, ec.SupportedContentTypes, "application/json")
		assert.Contains(t, ec.SupportedContentTypes, "application/xml")
	})

	t.Run("charset variants are deduplicated to canonical form", func(t *testing.T) {
		// Arrange — both request and response use application/json but one has charset
		input := `{"request":{"contentType":"application/json; charset=utf-8"},"response":{"contentType":"application/json"}}`

		// Act
		var ec EncodingConfig
		err := json.Unmarshal([]byte(input), &ec)

		// Assert
		require.NoError(t, err)
		count := 0
		for _, ct := range ec.SupportedContentTypes {
			if ct == "application/json" {
				count++
			}
		}
		assert.Equal(t, 1, count, "application/json should appear exactly once after charset dedup")
	})
}

// ---------------------------------------------------------------------------
// Tests for UnmarshalJSON — real CRD payload (integration-style)
// ---------------------------------------------------------------------------

func TestEncodingConfig_UnmarshalJSON_RealCRDPayload(t *testing.T) {
	t.Run("exact operator CRD JSON payload", func(t *testing.T) {
		// Arrange — this is the exact JSON the operator sends
		input := `{"request":{"contentType":"application/json"},"response":{"contentType":"application/json"}}`

		// Act
		var ec EncodingConfig
		err := json.Unmarshal([]byte(input), &ec)

		// Assert
		require.NoError(t, err)
		assert.Equal(t, "json", ec.RequestEncoding)
		assert.Equal(t, "json", ec.ResponseEncoding)
		assert.True(t, ec.EnableContentNegotiation)
		assert.Contains(t, ec.SupportedContentTypes, "application/json")
		assert.False(t, ec.IsEmpty())
	})

	t.Run("operator CRD with XML", func(t *testing.T) {
		// Arrange
		input := `{"request":{"contentType":"application/xml"},"response":{"contentType":"application/xml"}}`

		// Act
		var ec EncodingConfig
		err := json.Unmarshal([]byte(input), &ec)

		// Assert
		require.NoError(t, err)
		assert.Equal(t, "xml", ec.RequestEncoding)
		assert.Equal(t, "xml", ec.ResponseEncoding)
		assert.True(t, ec.EnableContentNegotiation)
		assert.Contains(t, ec.SupportedContentTypes, "application/xml")
		assert.False(t, ec.IsEmpty())
	})

	t.Run("operator CRD with mixed request/response types", func(t *testing.T) {
		// Arrange
		input := `{"request":{"contentType":"application/json"},"response":{"contentType":"application/xml"}}`

		// Act
		var ec EncodingConfig
		err := json.Unmarshal([]byte(input), &ec)

		// Assert
		require.NoError(t, err)
		assert.Equal(t, "json", ec.RequestEncoding)
		assert.Equal(t, "xml", ec.ResponseEncoding)
		assert.True(t, ec.EnableContentNegotiation)
		assert.Contains(t, ec.SupportedContentTypes, "application/json")
		assert.Contains(t, ec.SupportedContentTypes, "application/xml")
		assert.Len(t, ec.SupportedContentTypes, 2)
		assert.False(t, ec.IsEmpty())
	})

	t.Run("operator CRD full route spec encoding section", func(t *testing.T) {
		// Arrange — simulating a more complete CRD payload with additional fields
		input := `{
			"request": {"contentType": "application/json"},
			"response": {"contentType": "application/json"},
			"json": {"prettyPrint": true, "emitDefaults": true},
			"compression": {"enabled": true, "algorithms": ["gzip"], "minSize": 1024, "level": 6}
		}`

		// Act
		var ec EncodingConfig
		err := json.Unmarshal([]byte(input), &ec)

		// Assert
		require.NoError(t, err)
		assert.Equal(t, "json", ec.RequestEncoding)
		assert.Equal(t, "json", ec.ResponseEncoding)
		assert.True(t, ec.EnableContentNegotiation)
		assert.Contains(t, ec.SupportedContentTypes, "application/json")

		require.NotNil(t, ec.JSON)
		assert.True(t, ec.JSON.PrettyPrint)
		assert.True(t, ec.JSON.EmitDefaults)

		require.NotNil(t, ec.Compression)
		assert.True(t, ec.Compression.Enabled)
		assert.Contains(t, ec.Compression.Algorithms, "gzip")
		assert.Equal(t, 1024, ec.Compression.MinSize)
		assert.Equal(t, 6, ec.Compression.Level)

		assert.False(t, ec.IsEmpty())
	})
}

// ---------------------------------------------------------------------------
// Tests for UnmarshalJSON — error cases
// ---------------------------------------------------------------------------

func TestEncodingConfig_UnmarshalJSON_InvalidJSON(t *testing.T) {
	tests := []struct {
		name      string
		jsonInput string
	}{
		{
			name:      "completely invalid JSON",
			jsonInput: `{invalid`,
		},
		{
			name:      "wrong type for requestEncoding",
			jsonInput: `{"requestEncoding":123}`,
		},
		{
			name:      "wrong type for enableContentNegotiation",
			jsonInput: `{"enableContentNegotiation":"yes"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			var ec EncodingConfig

			// Act
			err := json.Unmarshal([]byte(tt.jsonInput), &ec)

			// Assert
			assert.Error(t, err)
		})
	}
}
