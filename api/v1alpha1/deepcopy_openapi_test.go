package v1alpha1

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func boolPtrV1(b bool) *bool {
	return &b
}

func TestOpenAPIValidationConfig_DeepCopy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		original *OpenAPIValidationConfig
	}{
		{
			name:     "nil config",
			original: nil,
		},
		{
			name: "empty config",
			original: &OpenAPIValidationConfig{
				Enabled: false,
			},
		},
		{
			name: "full config with all fields",
			original: &OpenAPIValidationConfig{
				Enabled: true,
				SpecConfigMapRef: &ConfigMapKeyRef{
					Name: "my-configmap",
					Key:  "spec.yaml",
				},
				SpecFile:               "/path/to/spec.yaml",
				SpecURL:                "https://example.com/spec.yaml",
				FailOnError:            boolPtrV1(true),
				ValidateRequestBody:    boolPtrV1(true),
				ValidateRequestParams:  boolPtrV1(false),
				ValidateRequestHeaders: boolPtrV1(true),
				ValidateSecurity:       boolPtrV1(false),
			},
		},
		{
			name: "config with nil optional fields",
			original: &OpenAPIValidationConfig{
				Enabled:  true,
				SpecFile: "/path/to/spec.yaml",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			copied := tt.original.DeepCopy()

			if tt.original == nil {
				assert.Nil(t, copied)
				return
			}

			require.NotNil(t, copied)
			assert.Equal(t, tt.original.Enabled, copied.Enabled)
			assert.Equal(t, tt.original.SpecFile, copied.SpecFile)
			assert.Equal(t, tt.original.SpecURL, copied.SpecURL)

			// Verify deep copy of pointer fields
			if tt.original.SpecConfigMapRef != nil {
				require.NotNil(t, copied.SpecConfigMapRef)
				assert.Equal(t, tt.original.SpecConfigMapRef.Name, copied.SpecConfigMapRef.Name)
				assert.Equal(t, tt.original.SpecConfigMapRef.Key, copied.SpecConfigMapRef.Key)
				// Verify it's a different pointer
				assert.NotSame(t, tt.original.SpecConfigMapRef, copied.SpecConfigMapRef)
			}

			if tt.original.FailOnError != nil {
				require.NotNil(t, copied.FailOnError)
				assert.Equal(t, *tt.original.FailOnError, *copied.FailOnError)
				assert.NotSame(t, tt.original.FailOnError, copied.FailOnError)
			}

			if tt.original.ValidateRequestBody != nil {
				require.NotNil(t, copied.ValidateRequestBody)
				assert.Equal(t, *tt.original.ValidateRequestBody, *copied.ValidateRequestBody)
				assert.NotSame(t, tt.original.ValidateRequestBody, copied.ValidateRequestBody)
			}

			if tt.original.ValidateRequestParams != nil {
				require.NotNil(t, copied.ValidateRequestParams)
				assert.Equal(t, *tt.original.ValidateRequestParams, *copied.ValidateRequestParams)
				assert.NotSame(t, tt.original.ValidateRequestParams, copied.ValidateRequestParams)
			}

			if tt.original.ValidateRequestHeaders != nil {
				require.NotNil(t, copied.ValidateRequestHeaders)
				assert.Equal(t, *tt.original.ValidateRequestHeaders, *copied.ValidateRequestHeaders)
				assert.NotSame(t, tt.original.ValidateRequestHeaders, copied.ValidateRequestHeaders)
			}

			if tt.original.ValidateSecurity != nil {
				require.NotNil(t, copied.ValidateSecurity)
				assert.Equal(t, *tt.original.ValidateSecurity, *copied.ValidateSecurity)
				assert.NotSame(t, tt.original.ValidateSecurity, copied.ValidateSecurity)
			}
		})
	}
}

func TestOpenAPIValidationConfig_DeepCopyInto(t *testing.T) {
	t.Parallel()

	original := &OpenAPIValidationConfig{
		Enabled: true,
		SpecConfigMapRef: &ConfigMapKeyRef{
			Name: "my-configmap",
			Key:  "spec.yaml",
		},
		FailOnError:         boolPtrV1(true),
		ValidateRequestBody: boolPtrV1(false),
	}

	out := &OpenAPIValidationConfig{}
	original.DeepCopyInto(out)

	assert.Equal(t, original.Enabled, out.Enabled)
	assert.NotSame(t, original.SpecConfigMapRef, out.SpecConfigMapRef)
	assert.NotSame(t, original.FailOnError, out.FailOnError)
	assert.NotSame(t, original.ValidateRequestBody, out.ValidateRequestBody)
}

func TestConfigMapKeyRef_DeepCopy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		original *ConfigMapKeyRef
	}{
		{
			name:     "nil config",
			original: nil,
		},
		{
			name: "with name and key",
			original: &ConfigMapKeyRef{
				Name: "my-configmap",
				Key:  "data.yaml",
			},
		},
		{
			name: "with name only",
			original: &ConfigMapKeyRef{
				Name: "my-configmap",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			copied := tt.original.DeepCopy()

			if tt.original == nil {
				assert.Nil(t, copied)
				return
			}

			require.NotNil(t, copied)
			assert.Equal(t, tt.original.Name, copied.Name)
			assert.Equal(t, tt.original.Key, copied.Key)
		})
	}
}

func TestConfigMapKeyRef_DeepCopyInto(t *testing.T) {
	t.Parallel()

	original := &ConfigMapKeyRef{
		Name: "my-configmap",
		Key:  "data.yaml",
	}

	out := &ConfigMapKeyRef{}
	original.DeepCopyInto(out)

	assert.Equal(t, original.Name, out.Name)
	assert.Equal(t, original.Key, out.Key)
}

func TestProtoValidationConfig_DeepCopy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		original *ProtoValidationConfig
	}{
		{
			name:     "nil config",
			original: nil,
		},
		{
			name: "empty config",
			original: &ProtoValidationConfig{
				Enabled: false,
			},
		},
		{
			name: "full config",
			original: &ProtoValidationConfig{
				Enabled: true,
				DescriptorConfigMapRef: &ConfigMapKeyRef{
					Name: "proto-configmap",
					Key:  "descriptor.pb",
				},
				DescriptorFile:         "/path/to/descriptor.pb",
				FailOnError:            boolPtrV1(false),
				ValidateRequestMessage: boolPtrV1(true),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			copied := tt.original.DeepCopy()

			if tt.original == nil {
				assert.Nil(t, copied)
				return
			}

			require.NotNil(t, copied)
			assert.Equal(t, tt.original.Enabled, copied.Enabled)
			assert.Equal(t, tt.original.DescriptorFile, copied.DescriptorFile)

			if tt.original.DescriptorConfigMapRef != nil {
				require.NotNil(t, copied.DescriptorConfigMapRef)
				assert.Equal(t, tt.original.DescriptorConfigMapRef.Name, copied.DescriptorConfigMapRef.Name)
				assert.NotSame(t, tt.original.DescriptorConfigMapRef, copied.DescriptorConfigMapRef)
			}

			if tt.original.FailOnError != nil {
				require.NotNil(t, copied.FailOnError)
				assert.Equal(t, *tt.original.FailOnError, *copied.FailOnError)
				assert.NotSame(t, tt.original.FailOnError, copied.FailOnError)
			}

			if tt.original.ValidateRequestMessage != nil {
				require.NotNil(t, copied.ValidateRequestMessage)
				assert.Equal(t, *tt.original.ValidateRequestMessage, *copied.ValidateRequestMessage)
				assert.NotSame(t, tt.original.ValidateRequestMessage, copied.ValidateRequestMessage)
			}
		})
	}
}

func TestProtoValidationConfig_DeepCopyInto(t *testing.T) {
	t.Parallel()

	original := &ProtoValidationConfig{
		Enabled:                true,
		FailOnError:            boolPtrV1(true),
		ValidateRequestMessage: boolPtrV1(false),
	}

	out := &ProtoValidationConfig{}
	original.DeepCopyInto(out)

	assert.Equal(t, original.Enabled, out.Enabled)
	assert.NotSame(t, original.FailOnError, out.FailOnError)
	assert.NotSame(t, original.ValidateRequestMessage, out.ValidateRequestMessage)
}

func TestGraphQLSchemaValidationConfig_DeepCopy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		original *GraphQLSchemaValidationConfig
	}{
		{
			name:     "nil config",
			original: nil,
		},
		{
			name: "empty config",
			original: &GraphQLSchemaValidationConfig{
				Enabled: false,
			},
		},
		{
			name: "full config",
			original: &GraphQLSchemaValidationConfig{
				Enabled: true,
				SchemaConfigMapRef: &ConfigMapKeyRef{
					Name: "schema-configmap",
					Key:  "schema.graphql",
				},
				SchemaFile:        "/path/to/schema.graphql",
				FailOnError:       boolPtrV1(true),
				ValidateVariables: boolPtrV1(false),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			copied := tt.original.DeepCopy()

			if tt.original == nil {
				assert.Nil(t, copied)
				return
			}

			require.NotNil(t, copied)
			assert.Equal(t, tt.original.Enabled, copied.Enabled)
			assert.Equal(t, tt.original.SchemaFile, copied.SchemaFile)

			if tt.original.SchemaConfigMapRef != nil {
				require.NotNil(t, copied.SchemaConfigMapRef)
				assert.Equal(t, tt.original.SchemaConfigMapRef.Name, copied.SchemaConfigMapRef.Name)
				assert.NotSame(t, tt.original.SchemaConfigMapRef, copied.SchemaConfigMapRef)
			}

			if tt.original.FailOnError != nil {
				require.NotNil(t, copied.FailOnError)
				assert.Equal(t, *tt.original.FailOnError, *copied.FailOnError)
				assert.NotSame(t, tt.original.FailOnError, copied.FailOnError)
			}

			if tt.original.ValidateVariables != nil {
				require.NotNil(t, copied.ValidateVariables)
				assert.Equal(t, *tt.original.ValidateVariables, *copied.ValidateVariables)
				assert.NotSame(t, tt.original.ValidateVariables, copied.ValidateVariables)
			}
		})
	}
}

func TestGraphQLSchemaValidationConfig_DeepCopyInto(t *testing.T) {
	t.Parallel()

	original := &GraphQLSchemaValidationConfig{
		Enabled:           true,
		FailOnError:       boolPtrV1(false),
		ValidateVariables: boolPtrV1(true),
	}

	out := &GraphQLSchemaValidationConfig{}
	original.DeepCopyInto(out)

	assert.Equal(t, original.Enabled, out.Enabled)
	assert.NotSame(t, original.FailOnError, out.FailOnError)
	assert.NotSame(t, original.ValidateVariables, out.ValidateVariables)
}
