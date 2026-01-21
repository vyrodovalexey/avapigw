// Package encoding provides encoding/decoding capabilities for the API Gateway.
package encoding

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestNewCodecFactory(t *testing.T) {
	tests := []struct {
		name   string
		logger observability.Logger
	}{
		{
			name:   "with logger",
			logger: observability.NopLogger(),
		},
		{
			name:   "nil logger",
			logger: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			factory := NewCodecFactory(tt.logger)
			assert.NotNil(t, factory)
		})
	}
}

func TestCodecFactory_GetCodec(t *testing.T) {
	factory := NewCodecFactory(observability.NopLogger())

	tests := []struct {
		name        string
		contentType string
		wantErr     bool
		errType     error
	}{
		{
			name:        "JSON content type",
			contentType: config.ContentTypeJSON,
			wantErr:     false,
		},
		{
			name:        "JSON with charset",
			contentType: "application/json; charset=utf-8",
			wantErr:     false,
		},
		{
			name:        "text/json",
			contentType: "text/json",
			wantErr:     false,
		},
		{
			name:        "XML content type",
			contentType: config.ContentTypeXML,
			wantErr:     false,
		},
		{
			name:        "text/xml",
			contentType: "text/xml",
			wantErr:     false,
		},
		{
			name:        "YAML content type",
			contentType: config.ContentTypeYAML,
			wantErr:     false,
		},
		{
			name:        "application/x-yaml",
			contentType: "application/x-yaml",
			wantErr:     false,
		},
		{
			name:        "text/yaml",
			contentType: "text/yaml",
			wantErr:     false,
		},
		{
			name:        "unsupported content type",
			contentType: "application/octet-stream",
			wantErr:     true,
			errType:     ErrUnsupportedContentType,
		},
		{
			name:        "empty content type",
			contentType: "",
			wantErr:     true,
			errType:     ErrUnsupportedContentType,
		},
		{
			name:        "unknown content type",
			contentType: "application/unknown",
			wantErr:     true,
			errType:     ErrUnsupportedContentType,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			codec, err := factory.GetCodec(tt.contentType)

			if tt.wantErr {
				require.Error(t, err)
				assert.ErrorIs(t, err, tt.errType)
				assert.Nil(t, codec)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, codec)
			}
		})
	}
}

func TestCodecFactory_SupportedTypes(t *testing.T) {
	factory := NewCodecFactory(observability.NopLogger())

	types := factory.SupportedTypes()

	assert.NotEmpty(t, types)

	// Should contain at least JSON, XML, and YAML
	foundJSON := false
	foundXML := false
	foundYAML := false

	for _, ct := range types {
		switch ct {
		case config.ContentTypeJSON:
			foundJSON = true
		case config.ContentTypeXML:
			foundXML = true
		case config.ContentTypeYAML:
			foundYAML = true
		}
	}

	assert.True(t, foundJSON, "should support JSON")
	assert.True(t, foundXML, "should support XML")
	assert.True(t, foundYAML, "should support YAML")
}

func TestCodecFactory_RegisterCodec(t *testing.T) {
	factory := NewCodecFactory(observability.NopLogger()).(*codecFactory)

	// Create a custom codec
	customCodec := NewJSONCodec(nil)

	// Register it for a custom content type
	factory.RegisterCodec("application/custom", customCodec)

	// Should be able to retrieve it
	codec, err := factory.GetCodec("application/custom")
	require.NoError(t, err)
	assert.NotNil(t, codec)
}

func TestNormalizeContentType(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		want        string
	}{
		{
			name:        "simple content type",
			contentType: "application/json",
			want:        "application/json",
		},
		{
			name:        "with charset",
			contentType: "application/json; charset=utf-8",
			want:        "application/json",
		},
		{
			name:        "with multiple parameters",
			contentType: "application/json; charset=utf-8; boundary=something",
			want:        "application/json",
		},
		{
			name:        "empty string",
			contentType: "",
			want:        "",
		},
		{
			name:        "no parameters",
			contentType: "text/plain",
			want:        "text/plain",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeContentType(tt.contentType)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestGetEncoder(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		cfg         *config.EncodingConfig
		wantErr     bool
	}{
		{
			name:        "JSON encoder",
			contentType: config.ContentTypeJSON,
			cfg:         nil,
			wantErr:     false,
		},
		{
			name:        "JSON encoder with config",
			contentType: config.ContentTypeJSON,
			cfg: &config.EncodingConfig{
				JSON: &config.JSONEncodingConfig{
					PrettyPrint: true,
				},
			},
			wantErr: false,
		},
		{
			name:        "empty content type with JSON config",
			contentType: "",
			cfg: &config.EncodingConfig{
				JSON: &config.JSONEncodingConfig{
					PrettyPrint: true,
				},
			},
			wantErr: false,
		},
		{
			name:        "XML encoder",
			contentType: config.ContentTypeXML,
			cfg:         nil,
			wantErr:     false,
		},
		{
			name:        "YAML encoder",
			contentType: config.ContentTypeYAML,
			cfg:         nil,
			wantErr:     false,
		},
		{
			name:        "unsupported content type",
			contentType: "application/octet-stream",
			cfg:         nil,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoder, err := GetEncoder(tt.contentType, tt.cfg, observability.NopLogger())

			if tt.wantErr {
				require.Error(t, err)
				assert.Nil(t, encoder)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, encoder)
			}
		})
	}
}

func TestGetDecoder(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		wantErr     bool
	}{
		{
			name:        "JSON decoder",
			contentType: config.ContentTypeJSON,
			wantErr:     false,
		},
		{
			name:        "XML decoder",
			contentType: config.ContentTypeXML,
			wantErr:     false,
		},
		{
			name:        "YAML decoder",
			contentType: config.ContentTypeYAML,
			wantErr:     false,
		},
		{
			name:        "unsupported content type",
			contentType: "application/octet-stream",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decoder, err := GetDecoder(tt.contentType, observability.NopLogger())

			if tt.wantErr {
				require.Error(t, err)
				assert.Nil(t, decoder)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, decoder)
			}
		})
	}
}

func TestErrors(t *testing.T) {
	// Test that error variables are defined
	assert.NotNil(t, ErrUnsupportedContentType)
	assert.NotNil(t, ErrEncodingFailed)
	assert.NotNil(t, ErrDecodingFailed)
	assert.NotNil(t, ErrNilValue)

	// Test error messages
	assert.Contains(t, ErrUnsupportedContentType.Error(), "unsupported")
	assert.Contains(t, ErrEncodingFailed.Error(), "encoding")
	assert.Contains(t, ErrDecodingFailed.Error(), "decoding")
	assert.Contains(t, ErrNilValue.Error(), "nil")
}
