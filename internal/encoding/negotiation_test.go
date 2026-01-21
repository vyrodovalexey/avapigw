// Package encoding provides encoding/decoding capabilities for the API Gateway.
package encoding

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestNewNegotiator(t *testing.T) {
	tests := []struct {
		name           string
		supportedTypes []string
		opts           []NegotiatorOption
	}{
		{
			name:           "with supported types",
			supportedTypes: []string{config.ContentTypeJSON, config.ContentTypeXML},
		},
		{
			name:           "empty supported types",
			supportedTypes: []string{},
		},
		{
			name:           "nil supported types",
			supportedTypes: nil,
		},
		{
			name:           "with default type option",
			supportedTypes: []string{config.ContentTypeJSON},
			opts:           []NegotiatorOption{WithDefaultType(config.ContentTypeXML)},
		},
		{
			name:           "with logger option",
			supportedTypes: []string{config.ContentTypeJSON},
			opts:           []NegotiatorOption{WithNegotiatorLogger(observability.NopLogger())},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			negotiator := NewNegotiator(tt.supportedTypes, tt.opts...)
			assert.NotNil(t, negotiator)
		})
	}
}

func TestNegotiator_Negotiate(t *testing.T) {
	tests := []struct {
		name           string
		supportedTypes []string
		acceptHeader   string
		want           string
	}{
		{
			name:           "exact match JSON",
			supportedTypes: []string{config.ContentTypeJSON, config.ContentTypeXML},
			acceptHeader:   "application/json",
			want:           config.ContentTypeJSON,
		},
		{
			name:           "exact match XML",
			supportedTypes: []string{config.ContentTypeJSON, config.ContentTypeXML},
			acceptHeader:   "application/xml",
			want:           config.ContentTypeXML,
		},
		{
			name:           "wildcard match",
			supportedTypes: []string{config.ContentTypeJSON, config.ContentTypeXML},
			acceptHeader:   "*/*",
			want:           config.ContentTypeJSON, // First supported type
		},
		{
			name:           "partial wildcard match",
			supportedTypes: []string{config.ContentTypeJSON, config.ContentTypeXML},
			acceptHeader:   "application/*",
			want:           config.ContentTypeJSON,
		},
		{
			name:           "empty accept header returns default",
			supportedTypes: []string{config.ContentTypeJSON, config.ContentTypeXML},
			acceptHeader:   "",
			want:           config.ContentTypeJSON, // Default
		},
		{
			name:           "no match returns default",
			supportedTypes: []string{config.ContentTypeJSON},
			acceptHeader:   "text/html",
			want:           config.ContentTypeJSON, // Default
		},
		{
			name:           "quality preference - higher quality first",
			supportedTypes: []string{config.ContentTypeJSON, config.ContentTypeXML},
			acceptHeader:   "application/xml;q=0.9, application/json;q=1.0",
			want:           config.ContentTypeJSON,
		},
		{
			name:           "quality preference - XML preferred",
			supportedTypes: []string{config.ContentTypeJSON, config.ContentTypeXML},
			acceptHeader:   "application/json;q=0.5, application/xml;q=0.9",
			want:           config.ContentTypeXML,
		},
		{
			name:           "multiple types with default quality",
			supportedTypes: []string{config.ContentTypeJSON, config.ContentTypeXML},
			acceptHeader:   "application/json, application/xml",
			want:           config.ContentTypeJSON, // First match
		},
		{
			name:           "complex accept header",
			supportedTypes: []string{config.ContentTypeJSON, config.ContentTypeXML, config.ContentTypeYAML},
			acceptHeader:   "text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8",
			want:           config.ContentTypeXML,
		},
		{
			name:           "accept header with charset",
			supportedTypes: []string{config.ContentTypeJSON},
			acceptHeader:   "application/json; charset=utf-8",
			want:           config.ContentTypeJSON,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			negotiator := NewNegotiator(tt.supportedTypes)
			result := negotiator.Negotiate(tt.acceptHeader)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestNegotiator_NegotiateWithDefault(t *testing.T) {
	tests := []struct {
		name           string
		supportedTypes []string
		acceptHeader   string
		defaultType    string
		want           string
	}{
		{
			name:           "empty accept header uses provided default",
			supportedTypes: []string{config.ContentTypeJSON, config.ContentTypeXML},
			acceptHeader:   "",
			defaultType:    config.ContentTypeXML,
			want:           config.ContentTypeXML,
		},
		{
			name:           "match found ignores default",
			supportedTypes: []string{config.ContentTypeJSON, config.ContentTypeXML},
			acceptHeader:   "application/xml",
			defaultType:    config.ContentTypeJSON,
			want:           config.ContentTypeXML,
		},
		{
			name:           "no match uses provided default",
			supportedTypes: []string{config.ContentTypeJSON},
			acceptHeader:   "text/html",
			defaultType:    config.ContentTypeXML,
			want:           config.ContentTypeXML, // Provided default when result equals negotiator's default
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			negotiator := NewNegotiator(tt.supportedTypes)
			result := negotiator.NegotiateWithDefault(tt.acceptHeader, tt.defaultType)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestParseAcceptHeader(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   []mediaType
	}{
		{
			name:   "single type",
			header: "application/json",
			want: []mediaType{
				{mediaType: "application/json", quality: 1.0},
			},
		},
		{
			name:   "multiple types",
			header: "application/json, application/xml",
			want: []mediaType{
				{mediaType: "application/json", quality: 1.0},
				{mediaType: "application/xml", quality: 1.0},
			},
		},
		{
			name:   "with quality values",
			header: "application/json;q=0.9, application/xml;q=0.8",
			want: []mediaType{
				{mediaType: "application/json", quality: 0.9},
				{mediaType: "application/xml", quality: 0.8},
			},
		},
		{
			name:   "mixed quality values",
			header: "application/json, application/xml;q=0.9",
			want: []mediaType{
				{mediaType: "application/json", quality: 1.0},
				{mediaType: "application/xml", quality: 0.9},
			},
		},
		{
			name:   "empty header",
			header: "",
			want:   []mediaType{},
		},
		{
			name:   "with spaces",
			header: "  application/json  ,  application/xml  ",
			want: []mediaType{
				{mediaType: "application/json", quality: 1.0},
				{mediaType: "application/xml", quality: 1.0},
			},
		},
		{
			name:   "invalid quality value",
			header: "application/json;q=invalid",
			want: []mediaType{
				{mediaType: "application/json", quality: 1.0}, // Falls back to default
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseAcceptHeader(tt.header)
			assert.Equal(t, len(tt.want), len(result))
			for i, expected := range tt.want {
				if i < len(result) {
					assert.Equal(t, expected.mediaType, result[i].mediaType)
					assert.InDelta(t, expected.quality, result[i].quality, 0.001)
				}
			}
		})
	}
}

func TestMatchMediaType(t *testing.T) {
	tests := []struct {
		name      string
		requested string
		supported string
		want      bool
	}{
		{
			name:      "exact match",
			requested: "application/json",
			supported: "application/json",
			want:      true,
		},
		{
			name:      "no match",
			requested: "application/json",
			supported: "application/xml",
			want:      false,
		},
		{
			name:      "wildcard match",
			requested: "*/*",
			supported: "application/json",
			want:      true,
		},
		{
			name:      "partial wildcard match",
			requested: "application/*",
			supported: "application/json",
			want:      true,
		},
		{
			name:      "partial wildcard no match",
			requested: "text/*",
			supported: "application/json",
			want:      false,
		},
		{
			name:      "partial wildcard with text",
			requested: "text/*",
			supported: "text/plain",
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchMediaType(tt.requested, tt.supported)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestGetContentTypeFromConfig(t *testing.T) {
	tests := []struct {
		name         string
		cfg          *config.EncodingConfig
		acceptHeader string
		want         string
	}{
		{
			name:         "nil config returns JSON",
			cfg:          nil,
			acceptHeader: "",
			want:         config.ContentTypeJSON,
		},
		{
			name: "negotiation disabled uses response encoding",
			cfg: &config.EncodingConfig{
				EnableContentNegotiation: false,
				ResponseEncoding:         config.EncodingXML,
			},
			acceptHeader: "application/json",
			want:         config.ContentTypeXML,
		},
		{
			name: "negotiation disabled with empty response encoding",
			cfg: &config.EncodingConfig{
				EnableContentNegotiation: false,
				ResponseEncoding:         "",
			},
			acceptHeader: "application/json",
			want:         config.ContentTypeJSON,
		},
		{
			name: "negotiation enabled",
			cfg: &config.EncodingConfig{
				EnableContentNegotiation: true,
				SupportedContentTypes:    []string{config.ContentTypeJSON, config.ContentTypeXML},
			},
			acceptHeader: "application/xml",
			want:         config.ContentTypeXML,
		},
		{
			name: "negotiation enabled with empty supported types",
			cfg: &config.EncodingConfig{
				EnableContentNegotiation: true,
				SupportedContentTypes:    []string{},
			},
			acceptHeader: "application/xml",
			want:         config.ContentTypeJSON, // Default
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetContentTypeFromConfig(tt.cfg, tt.acceptHeader)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestEncodingToContentType(t *testing.T) {
	tests := []struct {
		name     string
		encoding string
		want     string
	}{
		{
			name:     "JSON encoding",
			encoding: config.EncodingJSON,
			want:     config.ContentTypeJSON,
		},
		{
			name:     "XML encoding",
			encoding: config.EncodingXML,
			want:     config.ContentTypeXML,
		},
		{
			name:     "YAML encoding",
			encoding: config.EncodingYAML,
			want:     config.ContentTypeYAML,
		},
		{
			name:     "Protobuf encoding",
			encoding: config.EncodingProtobuf,
			want:     config.ContentTypeProtobuf,
		},
		{
			name:     "unknown encoding",
			encoding: "unknown",
			want:     config.ContentTypeJSON,
		},
		{
			name:     "empty encoding",
			encoding: "",
			want:     config.ContentTypeJSON,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := encodingToContentType(tt.encoding)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestContentTypeToEncoding(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		want        string
	}{
		{
			name:        "JSON content type",
			contentType: config.ContentTypeJSON,
			want:        config.EncodingJSON,
		},
		{
			name:        "text/json",
			contentType: "text/json",
			want:        config.EncodingJSON,
		},
		{
			name:        "XML content type",
			contentType: config.ContentTypeXML,
			want:        config.EncodingXML,
		},
		{
			name:        "text/xml",
			contentType: "text/xml",
			want:        config.EncodingXML,
		},
		{
			name:        "YAML content type",
			contentType: config.ContentTypeYAML,
			want:        config.EncodingYAML,
		},
		{
			name:        "application/x-yaml",
			contentType: "application/x-yaml",
			want:        config.EncodingYAML,
		},
		{
			name:        "text/yaml",
			contentType: "text/yaml",
			want:        config.EncodingYAML,
		},
		{
			name:        "Protobuf content type",
			contentType: config.ContentTypeProtobuf,
			want:        config.EncodingProtobuf,
		},
		{
			name:        "unknown content type",
			contentType: "application/octet-stream",
			want:        config.EncodingJSON,
		},
		{
			name:        "content type with charset",
			contentType: "application/json; charset=utf-8",
			want:        config.EncodingJSON,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ContentTypeToEncoding(tt.contentType)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestWithDefaultType(t *testing.T) {
	negotiator := NewNegotiator(
		[]string{config.ContentTypeJSON, config.ContentTypeXML},
		WithDefaultType(config.ContentTypeXML),
	)

	// Empty accept header should return the custom default
	result := negotiator.Negotiate("")
	assert.Equal(t, config.ContentTypeXML, result)
}

func TestWithNegotiatorLogger(t *testing.T) {
	logger := observability.NopLogger()
	negotiator := NewNegotiator(
		[]string{config.ContentTypeJSON},
		WithNegotiatorLogger(logger),
	)

	// Should not panic and work normally
	result := negotiator.Negotiate("application/json")
	assert.Equal(t, config.ContentTypeJSON, result)
}
