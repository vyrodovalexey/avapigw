// Package controller provides Kubernetes controllers for the operator.
package controller

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
	"github.com/vyrodovalexey/avapigw/internal/config"
)

const (
	testNamespace  = "avapigw-test"
	testConfigMap  = "items-openapi-spec"
	testSpecKey    = "openapi.yaml"
	minimalOpenAPI = `openapi: 3.0.0
info:
  title: Items API
  version: 1.0.0
paths:
  /api/v1/items:
    get:
      responses:
        '200':
          description: ok
`
)

// newResolverScheme returns a scheme with both the avapigw CRD types and the
// core Kubernetes types (needed for ConfigMap reads).
func newResolverScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, avapigwv1alpha1.AddToScheme(scheme))
	require.NoError(t, corev1.AddToScheme(scheme))
	return scheme
}

func newFakeClientWithConfigMap(t *testing.T, cm *corev1.ConfigMap) client.Client {
	t.Helper()
	builder := fake.NewClientBuilder().WithScheme(newResolverScheme(t))
	if cm != nil {
		builder = builder.WithObjects(cm)
	}
	return builder.Build()
}

func openAPISpecConfigMap() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: testConfigMap, Namespace: testNamespace},
		Data:       map[string]string{testSpecKey: minimalOpenAPI},
	}
}

func TestResolveOpenAPIValidation_InlinesConfigMapSpec(t *testing.T) {
	c := newFakeClientWithConfigMap(t, openAPISpecConfigMap())

	cfg := &avapigwv1alpha1.OpenAPIValidationConfig{
		Enabled: true,
		SpecConfigMapRef: &avapigwv1alpha1.ConfigMapKeyRef{
			Name: testConfigMap,
			Key:  testSpecKey,
		},
	}

	err := resolveOpenAPIValidation(context.Background(), c, testNamespace, cfg)
	require.NoError(t, err)

	assert.Equal(t, minimalOpenAPI, cfg.SpecInline, "spec content must be inlined")
	assert.Nil(t, cfg.SpecConfigMapRef, "configmap ref must be cleared after resolution")
}

func TestResolveOpenAPIValidation_EmptyKeyUsesSingleKey(t *testing.T) {
	c := newFakeClientWithConfigMap(t, openAPISpecConfigMap())

	cfg := &avapigwv1alpha1.OpenAPIValidationConfig{
		Enabled: true,
		SpecConfigMapRef: &avapigwv1alpha1.ConfigMapKeyRef{
			Name: testConfigMap,
			// Key intentionally omitted.
		},
	}

	require.NoError(t, resolveOpenAPIValidation(context.Background(), c, testNamespace, cfg))
	assert.Equal(t, minimalOpenAPI, cfg.SpecInline)
}

func TestResolveOpenAPIValidation_MultipleKeysRequiresExplicitKey(t *testing.T) {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: testConfigMap, Namespace: testNamespace},
		Data: map[string]string{
			"openapi.yaml": minimalOpenAPI,
			"other.yaml":   "extra",
		},
	}
	c := newFakeClientWithConfigMap(t, cm)

	cfg := &avapigwv1alpha1.OpenAPIValidationConfig{
		Enabled:          true,
		SpecConfigMapRef: &avapigwv1alpha1.ConfigMapKeyRef{Name: testConfigMap},
	}

	err := resolveOpenAPIValidation(context.Background(), c, testNamespace, cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "multiple keys")
}

func TestResolveOpenAPIValidation_MissingConfigMap(t *testing.T) {
	c := newFakeClientWithConfigMap(t, nil)

	cfg := &avapigwv1alpha1.OpenAPIValidationConfig{
		Enabled: true,
		SpecConfigMapRef: &avapigwv1alpha1.ConfigMapKeyRef{
			Name: testConfigMap,
			Key:  testSpecKey,
		},
	}

	err := resolveOpenAPIValidation(context.Background(), c, testNamespace, cfg)
	require.Error(t, err)
}

func TestResolveOpenAPIValidation_MissingKey(t *testing.T) {
	c := newFakeClientWithConfigMap(t, openAPISpecConfigMap())

	cfg := &avapigwv1alpha1.OpenAPIValidationConfig{
		Enabled: true,
		SpecConfigMapRef: &avapigwv1alpha1.ConfigMapKeyRef{
			Name: testConfigMap,
			Key:  "does-not-exist.yaml",
		},
	}

	err := resolveOpenAPIValidation(context.Background(), c, testNamespace, cfg)
	require.Error(t, err)
	assert.ErrorIs(t, err, errConfigMapKeyNotFound)
}

func TestResolveOpenAPIValidation_NoopWhenDisabled(t *testing.T) {
	c := newFakeClientWithConfigMap(t, openAPISpecConfigMap())

	cfg := &avapigwv1alpha1.OpenAPIValidationConfig{
		Enabled:          false,
		SpecConfigMapRef: &avapigwv1alpha1.ConfigMapKeyRef{Name: testConfigMap, Key: testSpecKey},
	}

	require.NoError(t, resolveOpenAPIValidation(context.Background(), c, testNamespace, cfg))
	assert.Empty(t, cfg.SpecInline)
	assert.NotNil(t, cfg.SpecConfigMapRef, "disabled config must be left untouched")
}

func TestResolveOpenAPIValidation_NoopWhenNoRef(t *testing.T) {
	c := newFakeClientWithConfigMap(t, nil)

	cfg := &avapigwv1alpha1.OpenAPIValidationConfig{
		Enabled:  true,
		SpecFile: "/etc/gateway/spec.yaml",
	}

	require.NoError(t, resolveOpenAPIValidation(context.Background(), c, testNamespace, cfg))
	assert.Empty(t, cfg.SpecInline)
	assert.Equal(t, "/etc/gateway/spec.yaml", cfg.SpecFile)
}

func TestResolveProtoValidation_InlinesBase64Descriptor(t *testing.T) {
	descriptor := []byte{0x00, 0x01, 0x02, 0x03, 0xFF}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "proto-desc", Namespace: testNamespace},
		BinaryData: map[string][]byte{"user.desc": descriptor},
	}
	c := newFakeClientWithConfigMap(t, cm)

	cfg := &avapigwv1alpha1.ProtoValidationConfig{
		Enabled: true,
		DescriptorConfigMapRef: &avapigwv1alpha1.ConfigMapKeyRef{
			Name: "proto-desc",
			Key:  "user.desc",
		},
	}

	require.NoError(t, resolveProtoValidation(context.Background(), c, testNamespace, cfg))
	assert.Equal(t, base64.StdEncoding.EncodeToString(descriptor), cfg.DescriptorInline)
	assert.Nil(t, cfg.DescriptorConfigMapRef)
}

func TestResolveSchemaValidation_InlinesSchema(t *testing.T) {
	const schema = "type Query { hello: String }"
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "gql-schema", Namespace: testNamespace},
		Data:       map[string]string{"schema.graphql": schema},
	}
	c := newFakeClientWithConfigMap(t, cm)

	cfg := &avapigwv1alpha1.GraphQLSchemaValidationConfig{
		Enabled: true,
		SchemaConfigMapRef: &avapigwv1alpha1.ConfigMapKeyRef{
			Name: "gql-schema",
			Key:  "schema.graphql",
		},
	}

	require.NoError(t, resolveSchemaValidation(context.Background(), c, testNamespace, cfg))
	assert.Equal(t, schema, cfg.SchemaInline)
	assert.Nil(t, cfg.SchemaConfigMapRef)
}

// TestReconcileAPIRoute_ResolvesConfigMapRefAndPassesGatewayValidation is the
// end-to-end operator-side check: a route referencing an OpenAPI spec via a
// ConfigMap is reconciled, and the resulting JSON (as delivered to the gateway)
// deserializes into a config.Route that passes gateway-side validation.
func TestReconcileAPIRoute_ResolvesConfigMapRefAndPassesGatewayValidation(t *testing.T) {
	scheme := newResolverScheme(t)

	apiRoute := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "perf-openapi-items-validated",
			Namespace:  testNamespace,
			Finalizers: []string{APIRouteFinalizerName},
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Match: []avapigwv1alpha1.RouteMatch{
				{URI: &avapigwv1alpha1.URIMatch{Prefix: "/api/v1/validated/items"}},
			},
			OpenAPIValidation: &avapigwv1alpha1.OpenAPIValidationConfig{
				Enabled: true,
				SpecConfigMapRef: &avapigwv1alpha1.ConfigMapKeyRef{
					Name: testConfigMap,
					Key:  testSpecKey,
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(apiRoute, openAPISpecConfigMap()).
		WithStatusSubresource(apiRoute).
		Build()

	reconciler := newAPIRouteReconciler(t, fakeClient, scheme, newFakeRecorder())

	require.NoError(t, reconciler.reconcileAPIRoute(context.Background(), apiRoute))

	// The reconciler mutates the in-memory spec: ref cleared, spec inlined.
	require.NotNil(t, apiRoute.Spec.OpenAPIValidation)
	assert.Nil(t, apiRoute.Spec.OpenAPIValidation.SpecConfigMapRef)
	assert.Equal(t, minimalOpenAPI, apiRoute.Spec.OpenAPIValidation.SpecInline)

	// Simulate the operator -> gateway wire transfer: marshal the CRD spec and
	// unmarshal into the gateway config type, then run gateway validation.
	specJSON, err := json.Marshal(apiRoute.Spec)
	require.NoError(t, err)

	var route config.Route
	require.NoError(t, json.Unmarshal(specJSON, &route))
	route.Name = apiRoute.Name

	require.NotNil(t, route.OpenAPIValidation)
	assert.True(t, route.OpenAPIValidation.Enabled)
	assert.Equal(t, minimalOpenAPI, route.OpenAPIValidation.SpecInline)
	assert.Empty(t, route.OpenAPIValidation.SpecFile)
	assert.Empty(t, route.OpenAPIValidation.SpecURL)

	route.Route = []config.RouteDestination{
		{Destination: config.Destination{Host: "backend", Port: 8080}, Weight: 100},
	}

	gwCfg := &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata:   config.Metadata{Name: "test-gateway"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 8080, Protocol: "HTTP"},
			},
			Routes: []config.Route{route},
		},
	}
	validator := config.NewValidator()
	assert.NoError(t, validator.Validate(gwCfg),
		"gateway must accept a route whose OpenAPI spec was resolved from a ConfigMap")
}
