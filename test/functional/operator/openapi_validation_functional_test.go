//go:build functional

// Package operator_test contains functional tests for the apigw-operator.
package operator_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
	"github.com/vyrodovalexey/avapigw/internal/operator/webhook"
)

// boolPtr returns a pointer to a bool value.
func boolPtrOAV(b bool) *bool {
	return &b
}

// ---------------------------------------------------------------------------
// 1. CRD APIRoute with OpenAPIValidation field
// ---------------------------------------------------------------------------

func TestFunctional_APIRoute_OpenAPIValidation(t *testing.T) {
	validator := &webhook.APIRouteValidator{}

	t.Run("valid APIRoute with OpenAPIValidation specFile", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.OpenAPIValidation = &avapigwv1alpha1.OpenAPIValidationConfig{
			Enabled:  true,
			SpecFile: "/etc/gateway/openapi.yaml",
		}
		warnings, err := validator.ValidateCreate(context.Background(), route)
		assert.NoError(t, err)
		assert.Empty(t, warnings)
	})

	t.Run("valid APIRoute with OpenAPIValidation specURL", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.OpenAPIValidation = &avapigwv1alpha1.OpenAPIValidationConfig{
			Enabled: true,
			SpecURL: "https://api.example.com/openapi.yaml",
		}
		warnings, err := validator.ValidateCreate(context.Background(), route)
		assert.NoError(t, err)
		assert.Empty(t, warnings)
	})

	t.Run("valid APIRoute with OpenAPIValidation specConfigMapRef", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.OpenAPIValidation = &avapigwv1alpha1.OpenAPIValidationConfig{
			Enabled: true,
			SpecConfigMapRef: &avapigwv1alpha1.ConfigMapKeyRef{
				Name: "openapi-spec",
				Key:  "spec.yaml",
			},
		}
		warnings, err := validator.ValidateCreate(context.Background(), route)
		assert.NoError(t, err)
		assert.Empty(t, warnings)
	})

	t.Run("valid APIRoute with OpenAPIValidation all options", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.OpenAPIValidation = &avapigwv1alpha1.OpenAPIValidationConfig{
			Enabled:                true,
			SpecFile:               "/etc/gateway/openapi.yaml",
			FailOnError:            boolPtrOAV(false),
			ValidateRequestBody:    boolPtrOAV(true),
			ValidateRequestParams:  boolPtrOAV(true),
			ValidateRequestHeaders: boolPtrOAV(false),
			ValidateSecurity:       boolPtrOAV(false),
		}
		warnings, err := validator.ValidateCreate(context.Background(), route)
		assert.NoError(t, err)
		assert.Empty(t, warnings)
	})

	t.Run("valid APIRoute with disabled OpenAPIValidation", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.OpenAPIValidation = &avapigwv1alpha1.OpenAPIValidationConfig{
			Enabled: false,
		}
		warnings, err := validator.ValidateCreate(context.Background(), route)
		assert.NoError(t, err)
		assert.Empty(t, warnings)
	})

	t.Run("APIRoute without OpenAPIValidation is valid", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.OpenAPIValidation = nil
		warnings, err := validator.ValidateCreate(context.Background(), route)
		assert.NoError(t, err)
		assert.Empty(t, warnings)
	})

	t.Run("APIRoute update with OpenAPIValidation change", func(t *testing.T) {
		oldRoute := createBasicAPIRoute()
		newRoute := createBasicAPIRoute()
		newRoute.Spec.OpenAPIValidation = &avapigwv1alpha1.OpenAPIValidationConfig{
			Enabled:  true,
			SpecFile: "/etc/gateway/openapi.yaml",
		}
		warnings, err := validator.ValidateUpdate(context.Background(), oldRoute, newRoute)
		assert.NoError(t, err)
		assert.Empty(t, warnings)
	})

	t.Run("full APIRoute with OpenAPIValidation and other features", func(t *testing.T) {
		route := createFullAPIRoute()
		route.Spec.OpenAPIValidation = &avapigwv1alpha1.OpenAPIValidationConfig{
			Enabled:             true,
			SpecFile:            "/etc/gateway/openapi.yaml",
			FailOnError:         boolPtrOAV(true),
			ValidateRequestBody: boolPtrOAV(true),
		}
		warnings, err := validator.ValidateCreate(context.Background(), route)
		assert.NoError(t, err)
		_ = warnings
	})
}

// ---------------------------------------------------------------------------
// 2. CRD GRPCRoute with ProtoValidation field
// ---------------------------------------------------------------------------

func TestFunctional_GRPCRoute_ProtoValidation(t *testing.T) {
	validator := &webhook.GRPCRouteValidator{}

	t.Run("valid GRPCRoute with ProtoValidation", func(t *testing.T) {
		route := createBasicGRPCRoute()
		route.Spec.ProtoValidation = &avapigwv1alpha1.ProtoValidationConfig{
			Enabled:        true,
			DescriptorFile: "/etc/gateway/user.desc",
		}
		warnings, err := validator.ValidateCreate(context.Background(), route)
		assert.NoError(t, err)
		assert.Empty(t, warnings)
	})

	t.Run("valid GRPCRoute with ProtoValidation all options", func(t *testing.T) {
		route := createBasicGRPCRoute()
		route.Spec.ProtoValidation = &avapigwv1alpha1.ProtoValidationConfig{
			Enabled:                true,
			DescriptorFile:         "/etc/gateway/user.desc",
			FailOnError:            boolPtrOAV(false),
			ValidateRequestMessage: boolPtrOAV(true),
		}
		warnings, err := validator.ValidateCreate(context.Background(), route)
		assert.NoError(t, err)
		assert.Empty(t, warnings)
	})

	t.Run("valid GRPCRoute with ProtoValidation configMapRef", func(t *testing.T) {
		route := createBasicGRPCRoute()
		route.Spec.ProtoValidation = &avapigwv1alpha1.ProtoValidationConfig{
			Enabled: true,
			DescriptorConfigMapRef: &avapigwv1alpha1.ConfigMapKeyRef{
				Name: "proto-descriptor",
				Key:  "user.desc",
			},
		}
		warnings, err := validator.ValidateCreate(context.Background(), route)
		assert.NoError(t, err)
		assert.Empty(t, warnings)
	})

	t.Run("valid GRPCRoute with disabled ProtoValidation", func(t *testing.T) {
		route := createBasicGRPCRoute()
		route.Spec.ProtoValidation = &avapigwv1alpha1.ProtoValidationConfig{
			Enabled: false,
		}
		warnings, err := validator.ValidateCreate(context.Background(), route)
		assert.NoError(t, err)
		assert.Empty(t, warnings)
	})

	t.Run("GRPCRoute without ProtoValidation is valid", func(t *testing.T) {
		route := createBasicGRPCRoute()
		route.Spec.ProtoValidation = nil
		warnings, err := validator.ValidateCreate(context.Background(), route)
		assert.NoError(t, err)
		assert.Empty(t, warnings)
	})

	t.Run("GRPCRoute update with ProtoValidation change", func(t *testing.T) {
		oldRoute := createBasicGRPCRoute()
		newRoute := createBasicGRPCRoute()
		newRoute.Spec.ProtoValidation = &avapigwv1alpha1.ProtoValidationConfig{
			Enabled:        true,
			DescriptorFile: "/etc/gateway/user.desc",
		}
		warnings, err := validator.ValidateUpdate(context.Background(), oldRoute, newRoute)
		assert.NoError(t, err)
		assert.Empty(t, warnings)
	})
}

// ---------------------------------------------------------------------------
// 3. CRD GraphQLRoute with SchemaValidation field
// ---------------------------------------------------------------------------

func TestFunctional_GraphQLRoute_SchemaValidation(t *testing.T) {
	t.Parallel()

	validator := &webhook.GraphQLRouteValidator{}

	t.Run("valid GraphQLRoute with SchemaValidation", func(t *testing.T) {
		t.Parallel()

		route := createBasicGraphQLRoute()
		route.Spec.SchemaValidation = &avapigwv1alpha1.GraphQLSchemaValidationConfig{
			Enabled:    true,
			SchemaFile: "/etc/gateway/schema.graphql",
		}
		warnings, err := validator.ValidateCreate(context.Background(), route)
		assert.NoError(t, err)
		assert.Empty(t, warnings)
	})

	t.Run("valid GraphQLRoute with SchemaValidation all options", func(t *testing.T) {
		t.Parallel()

		route := createBasicGraphQLRoute()
		route.Spec.SchemaValidation = &avapigwv1alpha1.GraphQLSchemaValidationConfig{
			Enabled:           true,
			SchemaFile:        "/etc/gateway/schema.graphql",
			FailOnError:       boolPtrOAV(false),
			ValidateVariables: boolPtrOAV(true),
		}
		warnings, err := validator.ValidateCreate(context.Background(), route)
		assert.NoError(t, err)
		assert.Empty(t, warnings)
	})

	t.Run("valid GraphQLRoute with SchemaValidation configMapRef", func(t *testing.T) {
		t.Parallel()

		route := createBasicGraphQLRoute()
		route.Spec.SchemaValidation = &avapigwv1alpha1.GraphQLSchemaValidationConfig{
			Enabled: true,
			SchemaConfigMapRef: &avapigwv1alpha1.ConfigMapKeyRef{
				Name: "graphql-schema",
				Key:  "schema.graphql",
			},
		}
		warnings, err := validator.ValidateCreate(context.Background(), route)
		assert.NoError(t, err)
		assert.Empty(t, warnings)
	})

	t.Run("valid GraphQLRoute with disabled SchemaValidation", func(t *testing.T) {
		t.Parallel()

		route := createBasicGraphQLRoute()
		route.Spec.SchemaValidation = &avapigwv1alpha1.GraphQLSchemaValidationConfig{
			Enabled: false,
		}
		warnings, err := validator.ValidateCreate(context.Background(), route)
		assert.NoError(t, err)
		assert.Empty(t, warnings)
	})

	t.Run("GraphQLRoute without SchemaValidation is valid", func(t *testing.T) {
		t.Parallel()

		route := createBasicGraphQLRoute()
		route.Spec.SchemaValidation = nil
		warnings, err := validator.ValidateCreate(context.Background(), route)
		assert.NoError(t, err)
		assert.Empty(t, warnings)
	})

	t.Run("GraphQLRoute update with SchemaValidation change", func(t *testing.T) {
		t.Parallel()

		oldRoute := createBasicGraphQLRoute()
		newRoute := createBasicGraphQLRoute()
		newRoute.Spec.SchemaValidation = &avapigwv1alpha1.GraphQLSchemaValidationConfig{
			Enabled:    true,
			SchemaFile: "/etc/gateway/schema.graphql",
		}
		warnings, err := validator.ValidateUpdate(context.Background(), oldRoute, newRoute)
		assert.NoError(t, err)
		assert.Empty(t, warnings)
	})
}

// ---------------------------------------------------------------------------
// 4. CRD conversion preserves validation settings
// ---------------------------------------------------------------------------

func TestFunctional_CRD_ValidationConfigPreservation(t *testing.T) {
	t.Parallel()

	t.Run("APIRoute OpenAPIValidation fields are preserved in deep copy", func(t *testing.T) {
		t.Parallel()

		original := &avapigwv1alpha1.APIRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-route",
				Namespace: "default",
			},
			Spec: avapigwv1alpha1.APIRouteSpec{
				Match: []avapigwv1alpha1.RouteMatch{
					{URI: &avapigwv1alpha1.URIMatch{Prefix: "/api"}},
				},
				Route: []avapigwv1alpha1.RouteDestination{
					{Destination: avapigwv1alpha1.Destination{Host: "backend", Port: 8080}, Weight: 100},
				},
				OpenAPIValidation: &avapigwv1alpha1.OpenAPIValidationConfig{
					Enabled:                true,
					SpecFile:               "/etc/gateway/openapi.yaml",
					FailOnError:            boolPtrOAV(false),
					ValidateRequestBody:    boolPtrOAV(true),
					ValidateRequestParams:  boolPtrOAV(true),
					ValidateRequestHeaders: boolPtrOAV(false),
					ValidateSecurity:       boolPtrOAV(false),
				},
			},
		}

		copied := original.DeepCopy()
		require.NotNil(t, copied.Spec.OpenAPIValidation)

		assert.Equal(t, original.Spec.OpenAPIValidation.Enabled, copied.Spec.OpenAPIValidation.Enabled)
		assert.Equal(t, original.Spec.OpenAPIValidation.SpecFile, copied.Spec.OpenAPIValidation.SpecFile)
		assert.Equal(t, *original.Spec.OpenAPIValidation.FailOnError, *copied.Spec.OpenAPIValidation.FailOnError)
		assert.Equal(t, *original.Spec.OpenAPIValidation.ValidateRequestBody, *copied.Spec.OpenAPIValidation.ValidateRequestBody)

		// Verify deep copy independence
		*copied.Spec.OpenAPIValidation.FailOnError = true
		assert.False(t, *original.Spec.OpenAPIValidation.FailOnError)
	})

	t.Run("GRPCRoute ProtoValidation fields are preserved in deep copy", func(t *testing.T) {
		t.Parallel()

		original := &avapigwv1alpha1.GRPCRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-grpc-route",
				Namespace: "default",
			},
			Spec: avapigwv1alpha1.GRPCRouteSpec{
				Match: []avapigwv1alpha1.GRPCRouteMatch{
					{Service: &avapigwv1alpha1.StringMatch{Prefix: "api.v1"}},
				},
				Route: []avapigwv1alpha1.RouteDestination{
					{Destination: avapigwv1alpha1.Destination{Host: "backend", Port: 9000}, Weight: 100},
				},
				ProtoValidation: &avapigwv1alpha1.ProtoValidationConfig{
					Enabled:                true,
					DescriptorFile:         "/etc/gateway/user.desc",
					FailOnError:            boolPtrOAV(true),
					ValidateRequestMessage: boolPtrOAV(true),
				},
			},
		}

		copied := original.DeepCopy()
		require.NotNil(t, copied.Spec.ProtoValidation)

		assert.Equal(t, original.Spec.ProtoValidation.Enabled, copied.Spec.ProtoValidation.Enabled)
		assert.Equal(t, original.Spec.ProtoValidation.DescriptorFile, copied.Spec.ProtoValidation.DescriptorFile)
		assert.Equal(t, *original.Spec.ProtoValidation.FailOnError, *copied.Spec.ProtoValidation.FailOnError)

		// Verify deep copy independence
		*copied.Spec.ProtoValidation.FailOnError = false
		assert.True(t, *original.Spec.ProtoValidation.FailOnError)
	})

	t.Run("GraphQLRoute SchemaValidation fields are preserved in deep copy", func(t *testing.T) {
		t.Parallel()

		original := &avapigwv1alpha1.GraphQLRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-graphql-route",
				Namespace: "default",
			},
			Spec: avapigwv1alpha1.GraphQLRouteSpec{
				Match: []avapigwv1alpha1.GraphQLRouteMatch{
					{Path: &avapigwv1alpha1.StringMatch{Exact: "/graphql"}},
				},
				Route: []avapigwv1alpha1.RouteDestination{
					{Destination: avapigwv1alpha1.Destination{Host: "backend", Port: 8821}, Weight: 100},
				},
				SchemaValidation: &avapigwv1alpha1.GraphQLSchemaValidationConfig{
					Enabled:           true,
					SchemaFile:        "/etc/gateway/schema.graphql",
					FailOnError:       boolPtrOAV(true),
					ValidateVariables: boolPtrOAV(true),
				},
			},
		}

		copied := original.DeepCopy()
		require.NotNil(t, copied.Spec.SchemaValidation)

		assert.Equal(t, original.Spec.SchemaValidation.Enabled, copied.Spec.SchemaValidation.Enabled)
		assert.Equal(t, original.Spec.SchemaValidation.SchemaFile, copied.Spec.SchemaValidation.SchemaFile)
		assert.Equal(t, *original.Spec.SchemaValidation.FailOnError, *copied.Spec.SchemaValidation.FailOnError)

		// Verify deep copy independence
		*copied.Spec.SchemaValidation.FailOnError = false
		assert.True(t, *original.Spec.SchemaValidation.FailOnError)
	})
}
