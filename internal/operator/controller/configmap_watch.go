// Package controller provides Kubernetes controllers for the operator.
package controller

import (
	"context"

	apimeta "k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

// Field index keys mapping routes to the name of the ConfigMap referenced by
// their validation configuration. The indexes power the ConfigMap watches so
// that editing a referenced OpenAPI spec / proto descriptor / GraphQL schema
// re-reconciles exactly the routes that inline its content.
const (
	apiRouteConfigMapIndexField     = ".spec.openAPIValidation.specConfigMapRef.name"
	grpcRouteConfigMapIndexField    = ".spec.protoValidation.descriptorConfigMapRef.name"
	graphqlRouteConfigMapIndexField = ".spec.schemaValidation.schemaConfigMapRef.name"
)

// configMapRefName returns the referenced ConfigMap name for enabled
// validation configurations, or "" when no reference is in play.
func configMapRefName(enabled bool, ref *avapigwv1alpha1.ConfigMapKeyRef) string {
	if !enabled || ref == nil {
		return ""
	}
	return ref.Name
}

// apiRouteConfigMapName returns the OpenAPI spec ConfigMap referenced by an
// APIRoute, or "" when validation is disabled or inline.
func apiRouteConfigMapName(route *avapigwv1alpha1.APIRoute) string {
	cfg := route.Spec.OpenAPIValidation
	if cfg == nil {
		return ""
	}
	return configMapRefName(cfg.Enabled, cfg.SpecConfigMapRef)
}

// grpcRouteConfigMapName returns the proto descriptor ConfigMap referenced
// by a GRPCRoute, or "" when validation is disabled or inline.
func grpcRouteConfigMapName(route *avapigwv1alpha1.GRPCRoute) string {
	cfg := route.Spec.ProtoValidation
	if cfg == nil {
		return ""
	}
	return configMapRefName(cfg.Enabled, cfg.DescriptorConfigMapRef)
}

// graphqlRouteConfigMapName returns the GraphQL schema ConfigMap referenced
// by a GraphQLRoute, or "" when validation is disabled or inline.
func graphqlRouteConfigMapName(route *avapigwv1alpha1.GraphQLRoute) string {
	cfg := route.Spec.SchemaValidation
	if cfg == nil {
		return ""
	}
	return configMapRefName(cfg.Enabled, cfg.SchemaConfigMapRef)
}

// configMapIndexValues converts a referenced ConfigMap name to field index
// values (empty slice when there is no reference).
func configMapIndexValues(name string) []string {
	if name == "" {
		return nil
	}
	return []string{name}
}

// configMapMapFunc builds a handler.MapFunc that enqueues every route of the
// given kind (matched through the ConfigMap-name field index) living in the
// changed ConfigMap's namespace. ConfigMap references are namespace-local by
// design (see resolveConfigMapRef), so the lookup never crosses namespaces.
func configMapMapFunc(
	reader client.Reader,
	kind, indexField string,
	newList func() client.ObjectList,
) handler.MapFunc {
	return func(ctx context.Context, obj client.Object) []reconcile.Request {
		logger := log.FromContext(ctx)

		list := newList()
		if err := reader.List(ctx, list,
			client.InNamespace(obj.GetNamespace()),
			client.MatchingFields{indexField: obj.GetName()},
		); err != nil {
			logger.Error(err, "failed to list routes referencing ConfigMap",
				"kind", kind,
				"configmap", obj.GetName(),
				"namespace", obj.GetNamespace(),
			)
			return nil
		}

		items, err := apimeta.ExtractList(list)
		if err != nil {
			logger.Error(err, "failed to extract route list for ConfigMap mapping", "kind", kind)
			return nil
		}

		requests := make([]reconcile.Request, 0, len(items))
		for _, item := range items {
			route, ok := item.(client.Object)
			if !ok {
				continue
			}
			requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{
				Namespace: route.GetNamespace(),
				Name:      route.GetName(),
			}})
		}

		if len(requests) > 0 {
			GetControllerMetrics().RecordConfigMapEnqueues(kind, len(requests))
			logger.Info("referenced ConfigMap changed; re-reconciling routes",
				"kind", kind,
				"configmap", obj.GetName(),
				"namespace", obj.GetNamespace(),
				"routes", len(requests),
			)
		}

		return requests
	}
}
