// Package controller provides Kubernetes controllers for CRD reconciliation.
package controller

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

const (
	// HTTPRouteGatewayIndexField is the field index for HTTPRoute -> Gateway references
	HTTPRouteGatewayIndexField = ".spec.parentRefs.gateway"
	// GRPCRouteGatewayIndexField is the field index for GRPCRoute -> Gateway references
	GRPCRouteGatewayIndexField = ".spec.parentRefs.gateway"
	// TCPRouteGatewayIndexField is the field index for TCPRoute -> Gateway references
	TCPRouteGatewayIndexField = ".spec.parentRefs.gateway"
	// TLSRouteGatewayIndexField is the field index for TLSRoute -> Gateway references
	TLSRouteGatewayIndexField = ".spec.parentRefs.gateway"
	// HTTPRouteBackendIndexField is the field index for HTTPRoute -> Backend references
	HTTPRouteBackendIndexField = ".spec.rules.backendRefs.backend"
)

// SetupIndexers sets up field indexers for efficient lookups.
// This should be called during manager setup before starting controllers.
func SetupIndexers(ctx context.Context, mgr manager.Manager) error {
	// Index HTTPRoutes by Gateway reference
	if err := mgr.GetFieldIndexer().IndexField(ctx, &avapigwv1alpha1.HTTPRoute{}, HTTPRouteGatewayIndexField, func(obj client.Object) []string {
		route := obj.(*avapigwv1alpha1.HTTPRoute)
		return extractGatewayRefs(route.Namespace, route.Spec.ParentRefs)
	}); err != nil {
		return err
	}

	// Index GRPCRoutes by Gateway reference
	if err := mgr.GetFieldIndexer().IndexField(ctx, &avapigwv1alpha1.GRPCRoute{}, GRPCRouteGatewayIndexField, func(obj client.Object) []string {
		route := obj.(*avapigwv1alpha1.GRPCRoute)
		return extractGatewayRefs(route.Namespace, route.Spec.ParentRefs)
	}); err != nil {
		return err
	}

	// Index TCPRoutes by Gateway reference
	if err := mgr.GetFieldIndexer().IndexField(ctx, &avapigwv1alpha1.TCPRoute{}, TCPRouteGatewayIndexField, func(obj client.Object) []string {
		route := obj.(*avapigwv1alpha1.TCPRoute)
		return extractGatewayRefs(route.Namespace, route.Spec.ParentRefs)
	}); err != nil {
		return err
	}

	// Index TLSRoutes by Gateway reference
	if err := mgr.GetFieldIndexer().IndexField(ctx, &avapigwv1alpha1.TLSRoute{}, TLSRouteGatewayIndexField, func(obj client.Object) []string {
		route := obj.(*avapigwv1alpha1.TLSRoute)
		return extractGatewayRefs(route.Namespace, route.Spec.ParentRefs)
	}); err != nil {
		return err
	}

	// Index HTTPRoutes by Backend reference
	if err := mgr.GetFieldIndexer().IndexField(ctx, &avapigwv1alpha1.HTTPRoute{}, HTTPRouteBackendIndexField, func(obj client.Object) []string {
		route := obj.(*avapigwv1alpha1.HTTPRoute)
		return extractBackendRefs(route.Namespace, route.Spec.Rules)
	}); err != nil {
		return err
	}

	return nil
}

// extractGatewayRefs extracts gateway references from parent refs.
// Returns a list of "namespace/name" strings for indexing.
func extractGatewayRefs(routeNamespace string, parentRefs []avapigwv1alpha1.ParentRef) []string {
	refs := make([]string, 0, len(parentRefs))
	for _, parentRef := range parentRefs {
		namespace := routeNamespace
		if parentRef.Namespace != nil {
			namespace = *parentRef.Namespace
		}
		// Create a unique key for the gateway reference
		refs = append(refs, namespace+"/"+parentRef.Name)
	}
	return refs
}

// extractBackendRefs extracts backend references from HTTP route rules.
// Returns a list of "namespace/name" strings for indexing.
func extractBackendRefs(routeNamespace string, rules []avapigwv1alpha1.HTTPRouteRule) []string {
	var refs []string
	for _, rule := range rules {
		for _, backendRef := range rule.BackendRefs {
			namespace := routeNamespace
			if backendRef.Namespace != nil {
				namespace = *backendRef.Namespace
			}
			kind := "Service"
			if backendRef.Kind != nil {
				kind = *backendRef.Kind
			}
			// Only index Backend kind references
			if kind == "Backend" {
				refs = append(refs, namespace+"/"+backendRef.Name)
			}
		}
	}
	return refs
}

// GatewayIndexKey returns the index key for a gateway.
func GatewayIndexKey(namespace, name string) string {
	return namespace + "/" + name
}

// BackendIndexKey returns the index key for a backend.
func BackendIndexKey(namespace, name string) string {
	return namespace + "/" + name
}
