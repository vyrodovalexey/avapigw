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
