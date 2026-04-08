package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOpenAPIValidationConfig_GetEffectiveFailOnError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      *OpenAPIValidationConfig
		expected bool
	}{
		{
			name:     "nil config defaults to true",
			cfg:      nil,
			expected: true,
		},
		{
			name:     "nil FailOnError defaults to true",
			cfg:      &OpenAPIValidationConfig{},
			expected: true,
		},
		{
			name:     "FailOnError set to true",
			cfg:      &OpenAPIValidationConfig{FailOnError: boolPtr(true)},
			expected: true,
		},
		{
			name:     "FailOnError set to false",
			cfg:      &OpenAPIValidationConfig{FailOnError: boolPtr(false)},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.cfg.GetEffectiveFailOnError())
		})
	}
}

func TestOpenAPIValidationConfig_GetEffectiveValidateRequestBody(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      *OpenAPIValidationConfig
		expected bool
	}{
		{
			name:     "nil config defaults to true",
			cfg:      nil,
			expected: true,
		},
		{
			name:     "nil ValidateRequestBody defaults to true",
			cfg:      &OpenAPIValidationConfig{},
			expected: true,
		},
		{
			name:     "ValidateRequestBody set to true",
			cfg:      &OpenAPIValidationConfig{ValidateRequestBody: boolPtr(true)},
			expected: true,
		},
		{
			name:     "ValidateRequestBody set to false",
			cfg:      &OpenAPIValidationConfig{ValidateRequestBody: boolPtr(false)},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.cfg.GetEffectiveValidateRequestBody())
		})
	}
}

func TestOpenAPIValidationConfig_GetEffectiveValidateRequestParams(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      *OpenAPIValidationConfig
		expected bool
	}{
		{
			name:     "nil config defaults to true",
			cfg:      nil,
			expected: true,
		},
		{
			name:     "nil ValidateRequestParams defaults to true",
			cfg:      &OpenAPIValidationConfig{},
			expected: true,
		},
		{
			name:     "ValidateRequestParams set to true",
			cfg:      &OpenAPIValidationConfig{ValidateRequestParams: boolPtr(true)},
			expected: true,
		},
		{
			name:     "ValidateRequestParams set to false",
			cfg:      &OpenAPIValidationConfig{ValidateRequestParams: boolPtr(false)},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.cfg.GetEffectiveValidateRequestParams())
		})
	}
}

func TestOpenAPIValidationConfig_GetEffectiveValidateRequestHeaders(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      *OpenAPIValidationConfig
		expected bool
	}{
		{
			name:     "nil config defaults to false",
			cfg:      nil,
			expected: false,
		},
		{
			name:     "nil ValidateRequestHeaders defaults to false",
			cfg:      &OpenAPIValidationConfig{},
			expected: false,
		},
		{
			name:     "ValidateRequestHeaders set to true",
			cfg:      &OpenAPIValidationConfig{ValidateRequestHeaders: boolPtr(true)},
			expected: true,
		},
		{
			name:     "ValidateRequestHeaders set to false",
			cfg:      &OpenAPIValidationConfig{ValidateRequestHeaders: boolPtr(false)},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.cfg.GetEffectiveValidateRequestHeaders())
		})
	}
}

func TestOpenAPIValidationConfig_GetEffectiveValidateSecurity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      *OpenAPIValidationConfig
		expected bool
	}{
		{
			name:     "nil config defaults to false",
			cfg:      nil,
			expected: false,
		},
		{
			name:     "nil ValidateSecurity defaults to false",
			cfg:      &OpenAPIValidationConfig{},
			expected: false,
		},
		{
			name:     "ValidateSecurity set to true",
			cfg:      &OpenAPIValidationConfig{ValidateSecurity: boolPtr(true)},
			expected: true,
		},
		{
			name:     "ValidateSecurity set to false",
			cfg:      &OpenAPIValidationConfig{ValidateSecurity: boolPtr(false)},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.cfg.GetEffectiveValidateSecurity())
		})
	}
}

func TestProtoValidationConfig_GetEffectiveFailOnError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      *ProtoValidationConfig
		expected bool
	}{
		{
			name:     "nil config defaults to true",
			cfg:      nil,
			expected: true,
		},
		{
			name:     "nil FailOnError defaults to true",
			cfg:      &ProtoValidationConfig{},
			expected: true,
		},
		{
			name:     "FailOnError set to true",
			cfg:      &ProtoValidationConfig{FailOnError: boolPtr(true)},
			expected: true,
		},
		{
			name:     "FailOnError set to false",
			cfg:      &ProtoValidationConfig{FailOnError: boolPtr(false)},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.cfg.GetEffectiveFailOnError())
		})
	}
}

func TestProtoValidationConfig_GetEffectiveValidateRequestMessage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      *ProtoValidationConfig
		expected bool
	}{
		{
			name:     "nil config defaults to true",
			cfg:      nil,
			expected: true,
		},
		{
			name:     "nil ValidateRequestMessage defaults to true",
			cfg:      &ProtoValidationConfig{},
			expected: true,
		},
		{
			name:     "ValidateRequestMessage set to true",
			cfg:      &ProtoValidationConfig{ValidateRequestMessage: boolPtr(true)},
			expected: true,
		},
		{
			name:     "ValidateRequestMessage set to false",
			cfg:      &ProtoValidationConfig{ValidateRequestMessage: boolPtr(false)},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.cfg.GetEffectiveValidateRequestMessage())
		})
	}
}

func TestGraphQLSchemaValidationConfig_GetEffectiveFailOnError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      *GraphQLSchemaValidationConfig
		expected bool
	}{
		{
			name:     "nil config defaults to true",
			cfg:      nil,
			expected: true,
		},
		{
			name:     "nil FailOnError defaults to true",
			cfg:      &GraphQLSchemaValidationConfig{},
			expected: true,
		},
		{
			name:     "FailOnError set to true",
			cfg:      &GraphQLSchemaValidationConfig{FailOnError: boolPtr(true)},
			expected: true,
		},
		{
			name:     "FailOnError set to false",
			cfg:      &GraphQLSchemaValidationConfig{FailOnError: boolPtr(false)},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.cfg.GetEffectiveFailOnError())
		})
	}
}

func TestGraphQLSchemaValidationConfig_GetEffectiveValidateVariables(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      *GraphQLSchemaValidationConfig
		expected bool
	}{
		{
			name:     "nil config defaults to true",
			cfg:      nil,
			expected: true,
		},
		{
			name:     "nil ValidateVariables defaults to true",
			cfg:      &GraphQLSchemaValidationConfig{},
			expected: true,
		},
		{
			name:     "ValidateVariables set to true",
			cfg:      &GraphQLSchemaValidationConfig{ValidateVariables: boolPtr(true)},
			expected: true,
		},
		{
			name:     "ValidateVariables set to false",
			cfg:      &GraphQLSchemaValidationConfig{ValidateVariables: boolPtr(false)},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.cfg.GetEffectiveValidateVariables())
		})
	}
}
