package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateOpenAPIValidationConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		cfg       *OpenAPIValidationConfig
		wantError bool
		errSubstr string
	}{
		{
			name:      "nil config - no error",
			cfg:       nil,
			wantError: false,
		},
		{
			name: "disabled config - no error",
			cfg: &OpenAPIValidationConfig{
				Enabled: false,
			},
			wantError: false,
		},
		{
			name: "enabled with specFile",
			cfg: &OpenAPIValidationConfig{
				Enabled:  true,
				SpecFile: "/path/to/spec.yaml",
			},
			wantError: false,
		},
		{
			name: "enabled with specURL",
			cfg: &OpenAPIValidationConfig{
				Enabled: true,
				SpecURL: "https://example.com/spec.yaml",
			},
			wantError: false,
		},
		{
			name: "enabled without specFile or specURL",
			cfg: &OpenAPIValidationConfig{
				Enabled: true,
			},
			wantError: true,
			errSubstr: "either specFile or specURL is required",
		},
		{
			name: "enabled with both specFile and specURL",
			cfg: &OpenAPIValidationConfig{
				Enabled:  true,
				SpecFile: "/path/to/spec.yaml",
				SpecURL:  "https://example.com/spec.yaml",
			},
			wantError: true,
			errSubstr: "specFile and specURL are mutually exclusive",
		},
		{
			name: "enabled with invalid specURL",
			cfg: &OpenAPIValidationConfig{
				Enabled: true,
				SpecURL: "not-a-valid-url",
			},
			wantError: true,
			errSubstr: "specURL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			v := NewValidator()
			v.validateOpenAPIValidationConfig(tt.cfg, "test.openAPIValidation")

			if tt.wantError {
				assert.True(t, v.errors.HasErrors(), "expected validation errors")
				if tt.errSubstr != "" {
					assert.Contains(t, v.errors.Error(), tt.errSubstr)
				}
			} else {
				assert.False(t, v.errors.HasErrors(), "expected no validation errors, got: %v", v.errors)
			}
		})
	}
}

func TestValidateProtoValidationConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		cfg       *ProtoValidationConfig
		wantError bool
		errSubstr string
	}{
		{
			name:      "nil config - no error",
			cfg:       nil,
			wantError: false,
		},
		{
			name: "disabled config - no error",
			cfg: &ProtoValidationConfig{
				Enabled: false,
			},
			wantError: false,
		},
		{
			name: "enabled with descriptorFile",
			cfg: &ProtoValidationConfig{
				Enabled:        true,
				DescriptorFile: "/path/to/descriptor.pb",
			},
			wantError: false,
		},
		{
			name: "enabled without descriptorFile",
			cfg: &ProtoValidationConfig{
				Enabled: true,
			},
			wantError: true,
			errSubstr: "descriptorFile is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			v := NewValidator()
			v.validateProtoValidationConfig(tt.cfg, "test.protoValidation")

			if tt.wantError {
				assert.True(t, v.errors.HasErrors(), "expected validation errors")
				if tt.errSubstr != "" {
					assert.Contains(t, v.errors.Error(), tt.errSubstr)
				}
			} else {
				assert.False(t, v.errors.HasErrors(), "expected no validation errors, got: %v", v.errors)
			}
		})
	}
}

func TestValidateGraphQLSchemaValidationConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		cfg       *GraphQLSchemaValidationConfig
		wantError bool
		errSubstr string
	}{
		{
			name:      "nil config - no error",
			cfg:       nil,
			wantError: false,
		},
		{
			name: "disabled config - no error",
			cfg: &GraphQLSchemaValidationConfig{
				Enabled: false,
			},
			wantError: false,
		},
		{
			name: "enabled with schemaFile",
			cfg: &GraphQLSchemaValidationConfig{
				Enabled:    true,
				SchemaFile: "/path/to/schema.graphql",
			},
			wantError: false,
		},
		{
			name: "enabled without schemaFile",
			cfg: &GraphQLSchemaValidationConfig{
				Enabled: true,
			},
			wantError: true,
			errSubstr: "schemaFile is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			v := NewValidator()
			v.validateGraphQLSchemaValidationConfig(tt.cfg, "test.schemaValidation")

			if tt.wantError {
				assert.True(t, v.errors.HasErrors(), "expected validation errors")
				if tt.errSubstr != "" {
					assert.Contains(t, v.errors.Error(), tt.errSubstr)
				}
			} else {
				assert.False(t, v.errors.HasErrors(), "expected no validation errors, got: %v", v.errors)
			}
		})
	}
}

func TestValidateConfig_WithOpenAPIValidation(t *testing.T) {
	t.Parallel()

	t.Run("valid config with OpenAPI validation at spec level", func(t *testing.T) {
		t.Parallel()

		cfg := &GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   Metadata{Name: "test"},
			Spec: GatewaySpec{
				Listeners: []Listener{
					{Name: "http", Port: 8080, Protocol: "HTTP"},
				},
				OpenAPIValidation: &OpenAPIValidationConfig{
					Enabled:  true,
					SpecFile: "/path/to/spec.yaml",
				},
			},
		}

		err := ValidateConfig(cfg)
		assert.NoError(t, err)
	})

	t.Run("invalid config with OpenAPI validation missing spec", func(t *testing.T) {
		t.Parallel()

		cfg := &GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   Metadata{Name: "test"},
			Spec: GatewaySpec{
				Listeners: []Listener{
					{Name: "http", Port: 8080, Protocol: "HTTP"},
				},
				OpenAPIValidation: &OpenAPIValidationConfig{
					Enabled: true,
				},
			},
		}

		err := ValidateConfig(cfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "either specFile or specURL is required")
	})

	t.Run("valid config with OpenAPI validation at route level", func(t *testing.T) {
		t.Parallel()

		cfg := &GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   Metadata{Name: "test"},
			Spec: GatewaySpec{
				Listeners: []Listener{
					{Name: "http", Port: 8080, Protocol: "HTTP"},
				},
				Routes: []Route{
					{
						Name: "test-route",
						Route: []RouteDestination{
							{Destination: Destination{Host: "backend", Port: 8080}, Weight: 100},
						},
						OpenAPIValidation: &OpenAPIValidationConfig{
							Enabled:  true,
							SpecFile: "/path/to/spec.yaml",
						},
					},
				},
			},
		}

		err := ValidateConfig(cfg)
		assert.NoError(t, err)
	})
}
