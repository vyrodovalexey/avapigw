// Package config provides configuration types and loading for the API Gateway.
package config

import (
	"encoding/json"
	"strings"
)

// EncodingConfig represents encoding/decoding configuration for a route.
type EncodingConfig struct {
	// RequestEncoding specifies the encoding for request bodies.
	// Valid values: "json", "xml", "yaml", "protobuf".
	RequestEncoding string `yaml:"requestEncoding,omitempty" json:"requestEncoding,omitempty"`

	// ResponseEncoding specifies the encoding for response bodies.
	// Valid values: "json", "xml", "yaml", "protobuf".
	ResponseEncoding string `yaml:"responseEncoding,omitempty" json:"responseEncoding,omitempty"`

	// EnableContentNegotiation when true, enables automatic content type negotiation.
	EnableContentNegotiation bool `yaml:"enableContentNegotiation,omitempty" json:"enableContentNegotiation,omitempty"`

	// SupportedContentTypes lists content types supported for negotiation.
	SupportedContentTypes []string `yaml:"supportedContentTypes,omitempty" json:"supportedContentTypes,omitempty"`

	// JSON contains JSON-specific encoding options.
	JSON *JSONEncodingConfig `yaml:"json,omitempty" json:"json,omitempty"`

	// Protobuf contains Protocol Buffers-specific encoding options.
	Protobuf *ProtobufEncodingConfig `yaml:"protobuf,omitempty" json:"protobuf,omitempty"`

	// Compression contains compression configuration.
	Compression *CompressionConfig `yaml:"compression,omitempty" json:"compression,omitempty"`

	// Passthrough when true, passes content through without encoding/decoding.
	Passthrough bool `yaml:"passthrough,omitempty" json:"passthrough,omitempty"`
}

// JSONEncodingConfig contains JSON-specific encoding options.
type JSONEncodingConfig struct {
	// EmitDefaults when true, includes fields with default values in output.
	EmitDefaults bool `yaml:"emitDefaults,omitempty" json:"emitDefaults,omitempty"`

	// UseProtoNames when true, uses proto field names instead of camelCase.
	UseProtoNames bool `yaml:"useProtoNames,omitempty" json:"useProtoNames,omitempty"`

	// EnumAsIntegers when true, encodes enums as integers instead of strings.
	EnumAsIntegers bool `yaml:"enumAsIntegers,omitempty" json:"enumAsIntegers,omitempty"`

	// Int64AsStrings when true, encodes 64-bit integers as strings.
	Int64AsStrings bool `yaml:"int64AsStrings,omitempty" json:"int64AsStrings,omitempty"`

	// PrettyPrint when true, formats JSON output with indentation.
	PrettyPrint bool `yaml:"prettyPrint,omitempty" json:"prettyPrint,omitempty"`
}

// ProtobufEncodingConfig contains Protocol Buffers-specific encoding options.
type ProtobufEncodingConfig struct {
	// UseJSONEncoding when true, uses JSON encoding for protobuf messages.
	UseJSONEncoding bool `yaml:"useJSONEncoding,omitempty" json:"useJSONEncoding,omitempty"`

	// DescriptorSource specifies where to get protobuf descriptors.
	// Valid values: "reflection", "file".
	DescriptorSource string `yaml:"descriptorSource,omitempty" json:"descriptorSource,omitempty"`

	// DescriptorFile is the path to the protobuf descriptor file.
	DescriptorFile string `yaml:"descriptorFile,omitempty" json:"descriptorFile,omitempty"`
}

// CompressionConfig contains compression configuration.
type CompressionConfig struct {
	// Enabled indicates whether compression is enabled.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Algorithms lists supported compression algorithms in preference order.
	// Valid values: "gzip", "deflate", "snappy", "zstd".
	Algorithms []string `yaml:"algorithms,omitempty" json:"algorithms,omitempty"`

	// MinSize is the minimum response size in bytes to trigger compression.
	MinSize int `yaml:"minSize,omitempty" json:"minSize,omitempty"`

	// Level is the compression level (algorithm-specific).
	Level int `yaml:"level,omitempty" json:"level,omitempty"`
}

// EncodingType constants for encoding types.
const (
	// EncodingJSON represents JSON encoding.
	EncodingJSON = "json"

	// EncodingXML represents XML encoding.
	EncodingXML = "xml"

	// EncodingYAML represents YAML encoding.
	EncodingYAML = "yaml"

	// EncodingProtobuf represents Protocol Buffers encoding.
	EncodingProtobuf = "protobuf"
)

// CompressionAlgorithm constants for compression algorithms.
const (
	// CompressionGzip represents gzip compression.
	CompressionGzip = "gzip"

	// CompressionDeflate represents deflate compression.
	CompressionDeflate = "deflate"

	// CompressionSnappy represents snappy compression.
	CompressionSnappy = "snappy"

	// CompressionZstd represents zstd compression.
	CompressionZstd = "zstd"
)

// DescriptorSource constants for protobuf descriptor sources.
const (
	// DescriptorSourceReflection uses gRPC reflection to get descriptors.
	DescriptorSourceReflection = "reflection"

	// DescriptorSourceFile uses a file to get descriptors.
	DescriptorSourceFile = "file"
)

// ContentType constants for common content types.
const (
	// ContentTypeJSON is the JSON content type.
	ContentTypeJSON = "application/json"

	// ContentTypeXML is the XML content type.
	ContentTypeXML = "application/xml"

	// ContentTypeYAML is the YAML content type.
	ContentTypeYAML = "application/yaml"

	// ContentTypeProtobuf is the Protocol Buffers content type.
	ContentTypeProtobuf = "application/protobuf"

	// ContentTypeGRPC is the gRPC content type.
	ContentTypeGRPC = "application/grpc"

	// ContentTypeOctetStream is the binary content type.
	ContentTypeOctetStream = "application/octet-stream"
)

// DefaultEncodingConfig returns default encoding configuration.
func DefaultEncodingConfig() *EncodingConfig {
	return &EncodingConfig{
		RequestEncoding:          EncodingJSON,
		ResponseEncoding:         EncodingJSON,
		EnableContentNegotiation: true,
		SupportedContentTypes: []string{
			ContentTypeJSON,
			ContentTypeXML,
		},
		JSON: &JSONEncodingConfig{
			EmitDefaults: false,
			PrettyPrint:  false,
		},
		Compression: &CompressionConfig{
			Enabled:    true,
			Algorithms: []string{CompressionGzip},
			MinSize:    1024,
			Level:      6,
		},
	}
}

// IsEmpty returns true if the EncodingConfig has no meaningful configuration.
func (ec *EncodingConfig) IsEmpty() bool {
	if ec == nil {
		return true
	}
	return ec.RequestEncoding == "" &&
		ec.ResponseEncoding == "" &&
		!ec.EnableContentNegotiation &&
		len(ec.SupportedContentTypes) == 0 &&
		ec.JSON.IsEmpty() &&
		ec.Protobuf.IsEmpty() &&
		ec.Compression.IsEmpty() &&
		!ec.Passthrough
}

// IsEmpty returns true if the JSONEncodingConfig has no configuration.
func (jec *JSONEncodingConfig) IsEmpty() bool {
	if jec == nil {
		return true
	}
	return !jec.EmitDefaults &&
		!jec.UseProtoNames &&
		!jec.EnumAsIntegers &&
		!jec.Int64AsStrings &&
		!jec.PrettyPrint
}

// IsEmpty returns true if the ProtobufEncodingConfig has no configuration.
func (pec *ProtobufEncodingConfig) IsEmpty() bool {
	if pec == nil {
		return true
	}
	return !pec.UseJSONEncoding &&
		pec.DescriptorSource == "" &&
		pec.DescriptorFile == ""
}

// IsEmpty returns true if the CompressionConfig has no meaningful configuration.
func (cc *CompressionConfig) IsEmpty() bool {
	if cc == nil {
		return true
	}
	return !cc.Enabled
}

// contentTypeToEncoding converts a content type string (e.g., "application/json")
// to the corresponding encoding name (e.g., "json"). Unknown types are returned as-is.
func contentTypeToEncoding(contentType string) string {
	// Strip charset and other parameters (e.g., "application/json; charset=utf-8" → "application/json").
	ct := strings.TrimSpace(contentType)
	if idx := strings.IndexByte(ct, ';'); idx >= 0 {
		ct = strings.TrimSpace(ct[:idx])
	}

	switch ct {
	case "application/json", "text/json":
		return EncodingJSON
	case "application/xml", "text/xml":
		return EncodingXML
	case "application/yaml", "application/x-yaml", "text/yaml":
		return EncodingYAML
	case "application/protobuf", "application/x-protobuf":
		return EncodingProtobuf
	default:
		return contentType
	}
}

// crdEncodingSettings represents a single encoding direction in CRD format.
type crdEncodingSettings struct {
	ContentType string `json:"contentType,omitempty"`
}

// crdEncodingConfig represents the CRD-format encoding configuration
// sent by the operator (request.contentType / response.contentType).
type crdEncodingConfig struct {
	Request  *crdEncodingSettings `json:"request,omitempty"`
	Response *crdEncodingSettings `json:"response,omitempty"`
}

// canonicalContentType strips charset and other parameters from a content type string
// (e.g., "application/json; charset=utf-8" → "application/json").
func canonicalContentType(ct string) string {
	canonical := strings.TrimSpace(ct)
	if idx := strings.IndexByte(canonical, ';'); idx >= 0 {
		canonical = strings.TrimSpace(canonical[:idx])
	}
	return canonical
}

// applyCRDEncoding converts CRD-format encoding settings into internal EncodingConfig fields.
// It maps content types to encoding names, enables content negotiation, and populates
// SupportedContentTypes with the discovered content types.
func (ec *EncodingConfig) applyCRDEncoding(crd crdEncodingConfig) {
	// Map CRD content types to internal encoding names.
	if crd.Request != nil && crd.Request.ContentType != "" {
		ec.RequestEncoding = contentTypeToEncoding(crd.Request.ContentType)
	}
	if crd.Response != nil && crd.Response.ContentType != "" {
		ec.ResponseEncoding = contentTypeToEncoding(crd.Response.ContentType)
	}

	// Auto-enable content negotiation when CRD encoding config is present.
	ec.EnableContentNegotiation = true

	// Auto-populate SupportedContentTypes with the content types found,
	// preserving any that were already set.
	existing := make(map[string]struct{}, len(ec.SupportedContentTypes))
	for _, ct := range ec.SupportedContentTypes {
		existing[ct] = struct{}{}
	}

	appendUnique := func(ct string) {
		if ct == "" {
			return
		}
		canonical := canonicalContentType(ct)
		if _, ok := existing[canonical]; !ok {
			ec.SupportedContentTypes = append(ec.SupportedContentTypes, canonical)
			existing[canonical] = struct{}{}
		}
	}

	if crd.Request != nil {
		appendUnique(crd.Request.ContentType)
	}
	if crd.Response != nil {
		appendUnique(crd.Response.ContentType)
	}
}

// UnmarshalJSON implements custom JSON unmarshaling for EncodingConfig.
// It handles both the internal format (requestEncoding/responseEncoding fields)
// and the CRD format (request.contentType/response.contentType nested objects)
// for compatibility with the operator's CRD spec JSON.
func (ec *EncodingConfig) UnmarshalJSON(data []byte) error {
	// Use a type alias to avoid infinite recursion when calling json.Unmarshal.
	type Alias EncodingConfig

	var alias Alias
	if err := json.Unmarshal(data, &alias); err != nil {
		return err
	}

	*ec = EncodingConfig(alias)

	// If encoding fields are already populated, the internal format was used — nothing more to do.
	if ec.RequestEncoding != "" || ec.ResponseEncoding != "" {
		return nil
	}

	// Both encoding fields are empty after standard unmarshal.
	// Check whether the CRD format was provided instead.
	var crd crdEncodingConfig
	if err := json.Unmarshal(data, &crd); err != nil {
		// CRD parsing failed on data that already passed standard unmarshal.
		// This should not happen in practice; return the error for diagnostics.
		return err
	}

	// If neither CRD field is present, nothing to convert.
	if crd.Request == nil && crd.Response == nil {
		return nil
	}

	ec.applyCRDEncoding(crd)

	return nil
}
