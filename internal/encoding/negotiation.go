// Package encoding provides encoding/decoding capabilities for the API Gateway.
package encoding

import (
	"sort"
	"strconv"
	"strings"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// Negotiator handles content type negotiation.
type Negotiator interface {
	// Negotiate selects the best content type based on the Accept header.
	Negotiate(acceptHeader string) string

	// NegotiateWithDefault selects the best content type or returns the default.
	NegotiateWithDefault(acceptHeader, defaultType string) string
}

// negotiator implements the Negotiator interface.
type negotiator struct {
	logger         observability.Logger
	supportedTypes []string
	defaultType    string
}

// NegotiatorOption is a functional option for configuring the negotiator.
type NegotiatorOption func(*negotiator)

// WithDefaultType sets the default content type.
func WithDefaultType(contentType string) NegotiatorOption {
	return func(n *negotiator) {
		n.defaultType = contentType
	}
}

// WithNegotiatorLogger sets the logger for the negotiator.
func WithNegotiatorLogger(logger observability.Logger) NegotiatorOption {
	return func(n *negotiator) {
		n.logger = logger
	}
}

// NewNegotiator creates a new content type negotiator.
func NewNegotiator(supportedTypes []string, opts ...NegotiatorOption) Negotiator {
	n := &negotiator{
		logger:         observability.NopLogger(),
		supportedTypes: supportedTypes,
		defaultType:    config.ContentTypeJSON,
	}

	for _, opt := range opts {
		opt(n)
	}

	// Ensure we have at least one supported type
	if len(n.supportedTypes) == 0 {
		n.supportedTypes = []string{config.ContentTypeJSON}
	}

	return n
}

// Negotiate selects the best content type based on the Accept header.
func (n *negotiator) Negotiate(acceptHeader string) string {
	if acceptHeader == "" {
		return n.defaultType
	}

	// Parse Accept header
	mediaTypes := parseAcceptHeader(acceptHeader)

	// Sort by quality (descending)
	sort.Slice(mediaTypes, func(i, j int) bool {
		return mediaTypes[i].quality > mediaTypes[j].quality
	})

	// Find the first matching supported type
	for _, mt := range mediaTypes {
		for _, supported := range n.supportedTypes {
			if matchMediaType(mt.mediaType, supported) {
				n.logger.Debug("content type negotiated",
					observability.String("accept", acceptHeader),
					observability.String("selected", supported))
				return supported
			}
		}
	}

	// No match found, return default
	n.logger.Debug("no matching content type, using default",
		observability.String("accept", acceptHeader),
		observability.String("default", n.defaultType))

	return n.defaultType
}

// NegotiateWithDefault selects the best content type or returns the specified default.
func (n *negotiator) NegotiateWithDefault(acceptHeader, defaultType string) string {
	if acceptHeader == "" {
		return defaultType
	}

	result := n.Negotiate(acceptHeader)
	if result == n.defaultType && defaultType != "" {
		return defaultType
	}

	return result
}

// mediaType represents a parsed media type from the Accept header.
type mediaType struct {
	mediaType string
	quality   float64
}

// parseAcceptHeader parses an Accept header into media types with quality values.
// Example: "application/json, application/xml;q=0.9, */*;q=0.8"
func parseAcceptHeader(header string) []mediaType {
	parts := strings.Split(header, ",")
	result := make([]mediaType, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		mt := mediaType{quality: 1.0}

		// Split media type and parameters
		segments := strings.Split(part, ";")
		mt.mediaType = strings.TrimSpace(segments[0])

		// Parse quality parameter
		for _, segment := range segments[1:] {
			segment = strings.TrimSpace(segment)
			if strings.HasPrefix(segment, "q=") {
				qStr := strings.TrimPrefix(segment, "q=")
				if q, err := strconv.ParseFloat(qStr, 64); err == nil {
					mt.quality = q
				}
			}
		}

		result = append(result, mt)
	}

	return result
}

// matchMediaType checks if a requested media type matches a supported type.
// Supports wildcards (*/*) and partial wildcards (application/*).
func matchMediaType(requested, supported string) bool {
	// Exact match
	if requested == supported {
		return true
	}

	// Wildcard match
	if requested == "*/*" {
		return true
	}

	// Partial wildcard match (e.g., "application/*" matches "application/json")
	if strings.HasSuffix(requested, "/*") {
		prefix := strings.TrimSuffix(requested, "/*")
		return strings.HasPrefix(supported, prefix+"/")
	}

	return false
}

// GetContentTypeFromConfig returns the appropriate content type based on configuration.
func GetContentTypeFromConfig(cfg *config.EncodingConfig, acceptHeader string) string {
	if cfg == nil {
		return config.ContentTypeJSON
	}

	// If content negotiation is disabled, use configured response encoding
	if !cfg.EnableContentNegotiation {
		if cfg.ResponseEncoding != "" {
			return encodingToContentType(cfg.ResponseEncoding)
		}
		return config.ContentTypeJSON
	}

	// Use negotiation
	supportedTypes := cfg.SupportedContentTypes
	if len(supportedTypes) == 0 {
		supportedTypes = []string{config.ContentTypeJSON}
	}

	negotiator := NewNegotiator(supportedTypes)
	return negotiator.Negotiate(acceptHeader)
}

// encodingToContentType converts an encoding name to a content type.
func encodingToContentType(encoding string) string {
	switch encoding {
	case config.EncodingJSON:
		return config.ContentTypeJSON
	case config.EncodingXML:
		return config.ContentTypeXML
	case config.EncodingYAML:
		return config.ContentTypeYAML
	case config.EncodingProtobuf:
		return config.ContentTypeProtobuf
	default:
		return config.ContentTypeJSON
	}
}

// ContentTypeToEncoding converts a content type to an encoding name.
func ContentTypeToEncoding(contentType string) string {
	// Normalize content type
	ct := normalizeContentType(contentType)

	switch ct {
	case config.ContentTypeJSON, "text/json":
		return config.EncodingJSON
	case config.ContentTypeXML, "text/xml":
		return config.EncodingXML
	case config.ContentTypeYAML, "application/x-yaml", "text/yaml":
		return config.EncodingYAML
	case config.ContentTypeProtobuf:
		return config.EncodingProtobuf
	default:
		return config.EncodingJSON
	}
}
