// Package encoding provides encoding/decoding capabilities for the API Gateway.
package encoding

import (
	"errors"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// Common encoding errors.
var (
	// ErrUnsupportedContentType indicates that the content type is not supported.
	ErrUnsupportedContentType = errors.New("unsupported content type")

	// ErrEncodingFailed indicates that encoding failed.
	ErrEncodingFailed = errors.New("encoding failed")

	// ErrDecodingFailed indicates that decoding failed.
	ErrDecodingFailed = errors.New("decoding failed")

	// ErrNilValue indicates that the value to encode is nil.
	ErrNilValue = errors.New("nil value")
)

// Encoder encodes data to bytes.
type Encoder interface {
	// Encode encodes the value to bytes.
	Encode(v interface{}) ([]byte, error)

	// ContentType returns the content type for this encoder.
	ContentType() string
}

// Decoder decodes bytes to data.
type Decoder interface {
	// Decode decodes the data into the value.
	Decode(data []byte, v interface{}) error
}

// Codec combines Encoder and Decoder.
type Codec interface {
	Encoder
	Decoder
}

// CodecFactory creates codecs based on content type.
type CodecFactory interface {
	// GetCodec returns a codec for the given content type.
	GetCodec(contentType string) (Codec, error)

	// SupportedTypes returns the list of supported content types.
	SupportedTypes() []string
}

// codecFactory implements CodecFactory.
type codecFactory struct {
	logger observability.Logger
	codecs map[string]Codec
}

// NewCodecFactory creates a new CodecFactory with default codecs.
func NewCodecFactory(logger observability.Logger) CodecFactory {
	if logger == nil {
		logger = observability.NopLogger()
	}

	factory := &codecFactory{
		logger: logger,
		codecs: make(map[string]Codec),
	}

	// Register default codecs
	jsonCodec := NewJSONCodec(nil)
	factory.codecs[config.ContentTypeJSON] = jsonCodec
	factory.codecs["application/json; charset=utf-8"] = jsonCodec
	factory.codecs["text/json"] = jsonCodec

	xmlCodec := NewXMLCodec()
	factory.codecs[config.ContentTypeXML] = xmlCodec
	factory.codecs["text/xml"] = xmlCodec

	yamlCodec := NewYAMLCodec()
	factory.codecs[config.ContentTypeYAML] = yamlCodec
	factory.codecs["application/x-yaml"] = yamlCodec
	factory.codecs["text/yaml"] = yamlCodec

	return factory
}

// GetCodec returns a codec for the given content type.
func (f *codecFactory) GetCodec(contentType string) (Codec, error) {
	// Normalize content type (remove parameters)
	ct := normalizeContentType(contentType)

	codec, exists := f.codecs[ct]
	if !exists {
		f.logger.Debug("unsupported content type",
			observability.String("contentType", contentType))
		return nil, ErrUnsupportedContentType
	}

	return codec, nil
}

// SupportedTypes returns the list of supported content types.
func (f *codecFactory) SupportedTypes() []string {
	types := make([]string, 0, len(f.codecs))
	seen := make(map[string]bool)

	for ct := range f.codecs {
		normalized := normalizeContentType(ct)
		if !seen[normalized] {
			types = append(types, normalized)
			seen[normalized] = true
		}
	}

	return types
}

// RegisterCodec registers a codec for a content type.
func (f *codecFactory) RegisterCodec(contentType string, codec Codec) {
	f.codecs[normalizeContentType(contentType)] = codec
}

// normalizeContentType normalizes a content type by removing parameters.
func normalizeContentType(contentType string) string {
	for i, c := range contentType {
		if c == ';' {
			return contentType[:i]
		}
	}
	return contentType
}

// GetEncoder returns an encoder for the given content type.
func GetEncoder(contentType string, cfg *config.EncodingConfig, logger observability.Logger) (Encoder, error) {
	factory := NewCodecFactory(logger)

	// Apply JSON configuration if available
	if cfg != nil && cfg.JSON != nil && (contentType == config.ContentTypeJSON || contentType == "") {
		return NewJSONCodec(cfg.JSON), nil
	}

	codec, err := factory.GetCodec(contentType)
	if err != nil {
		return nil, err
	}

	return codec, nil
}

// GetDecoder returns a decoder for the given content type.
func GetDecoder(contentType string, logger observability.Logger) (Decoder, error) {
	factory := NewCodecFactory(logger)

	codec, err := factory.GetCodec(contentType)
	if err != nil {
		return nil, err
	}

	return codec, nil
}
