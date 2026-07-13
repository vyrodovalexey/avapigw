// Package controller provides Kubernetes controllers for the operator.
package controller

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

// errConfigMapKeyNotFound indicates a referenced ConfigMap key is missing.
var errConfigMapKeyNotFound = errors.New("configmap key not found")

// resolveConfigMapRef reads the referenced ConfigMap and returns the content of
// the requested key. When ref.Key is empty, the single key of the ConfigMap is
// used; if the ConfigMap has more than one key, an error is returned to avoid
// ambiguity. Binary data is preferred over string data when both are present
// for the same key.
//
// The namespace of the ConfigMap is always the namespace of the owning resource
// to prevent cross-namespace references (a defense against privilege escalation
// via arbitrary ConfigMap reads).
func resolveConfigMapRef(
	ctx context.Context,
	c client.Client,
	namespace string,
	ref *avapigwv1alpha1.ConfigMapKeyRef,
) ([]byte, error) {
	if ref == nil {
		return nil, errors.New("configmap reference is nil")
	}

	var cm corev1.ConfigMap
	key := types.NamespacedName{Namespace: namespace, Name: ref.Name}
	if err := c.Get(ctx, key, &cm); err != nil {
		return nil, fmt.Errorf("failed to get ConfigMap %s/%s: %w", namespace, ref.Name, err)
	}

	dataKey, err := resolveConfigMapKey(&cm, ref.Key)
	if err != nil {
		return nil, err
	}

	if binVal, ok := cm.BinaryData[dataKey]; ok {
		return binVal, nil
	}
	if strVal, ok := cm.Data[dataKey]; ok {
		return []byte(strVal), nil
	}

	return nil, fmt.Errorf("%w: key %q in ConfigMap %s/%s", errConfigMapKeyNotFound, dataKey, namespace, ref.Name)
}

// resolveConfigMapKey determines which ConfigMap key to read. When requested is
// non-empty it is returned as-is. Otherwise the single key present is used; an
// error is returned when the ConfigMap is empty or has multiple keys.
func resolveConfigMapKey(cm *corev1.ConfigMap, requested string) (string, error) {
	if requested != "" {
		return requested, nil
	}

	keys := make([]string, 0, len(cm.Data)+len(cm.BinaryData))
	for k := range cm.Data {
		keys = append(keys, k)
	}
	for k := range cm.BinaryData {
		keys = append(keys, k)
	}

	switch len(keys) {
	case 0:
		return "", fmt.Errorf("ConfigMap %s/%s has no data", cm.Namespace, cm.Name)
	case 1:
		return keys[0], nil
	default:
		return "", fmt.Errorf(
			"ConfigMap %s/%s has multiple keys; a specific key must be referenced",
			cm.Namespace, cm.Name,
		)
	}
}

// resolveOpenAPIValidation resolves an OpenAPIValidationConfig's SpecConfigMapRef
// into inline spec content so the gateway can validate requests without cluster
// access. It returns without modification when validation is disabled or no
// ConfigMap reference is set. The resolved content replaces SpecInline and the
// reference is cleared so downstream consumers only see the inline form.
func resolveOpenAPIValidation(
	ctx context.Context,
	c client.Client,
	namespace string,
	cfg *avapigwv1alpha1.OpenAPIValidationConfig,
) error {
	if cfg == nil || !cfg.Enabled || cfg.SpecConfigMapRef == nil {
		return nil
	}

	data, err := resolveConfigMapRef(ctx, c, namespace, cfg.SpecConfigMapRef)
	if err != nil {
		return fmt.Errorf("resolve openAPIValidation spec: %w", err)
	}

	cfg.SpecInline = string(data)
	cfg.SpecConfigMapRef = nil
	return nil
}

// resolveProtoValidation resolves a ProtoValidationConfig's DescriptorConfigMapRef
// into inline, base64-encoded descriptor content. The descriptor is binary, so it
// is base64-encoded for safe JSON transport to the gateway.
func resolveProtoValidation(
	ctx context.Context,
	c client.Client,
	namespace string,
	cfg *avapigwv1alpha1.ProtoValidationConfig,
) error {
	if cfg == nil || !cfg.Enabled || cfg.DescriptorConfigMapRef == nil {
		return nil
	}

	data, err := resolveConfigMapRef(ctx, c, namespace, cfg.DescriptorConfigMapRef)
	if err != nil {
		return fmt.Errorf("resolve protoValidation descriptor: %w", err)
	}

	cfg.DescriptorInline = base64.StdEncoding.EncodeToString(data)
	cfg.DescriptorConfigMapRef = nil
	return nil
}

// resolveSchemaValidation resolves a GraphQLSchemaValidationConfig's
// SchemaConfigMapRef into inline schema content.
func resolveSchemaValidation(
	ctx context.Context,
	c client.Client,
	namespace string,
	cfg *avapigwv1alpha1.GraphQLSchemaValidationConfig,
) error {
	if cfg == nil || !cfg.Enabled || cfg.SchemaConfigMapRef == nil {
		return nil
	}

	data, err := resolveConfigMapRef(ctx, c, namespace, cfg.SchemaConfigMapRef)
	if err != nil {
		return fmt.Errorf("resolve schemaValidation schema: %w", err)
	}

	cfg.SchemaInline = string(data)
	cfg.SchemaConfigMapRef = nil
	return nil
}
