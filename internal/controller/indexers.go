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
	// GRPCRouteBackendIndexField is the field index for GRPCRoute -> Backend references
	GRPCRouteBackendIndexField = ".spec.rules.backendRefs.backend"
	// TCPRouteBackendIndexField is the field index for TCPRoute -> Backend references
	TCPRouteBackendIndexField = ".spec.rules.backendRefs.backend"
	// TLSRouteBackendIndexField is the field index for TLSRoute -> Backend references
	TLSRouteBackendIndexField = ".spec.rules.backendRefs.backend"
)

// SetupIndexers sets up field indexers for efficient lookups.
// This should be called during manager setup before starting controllers.
func SetupIndexers(ctx context.Context, mgr manager.Manager) error {
	if err := setupGatewayIndexers(ctx, mgr); err != nil {
		return err
	}
	return setupBackendIndexers(ctx, mgr)
}

// setupGatewayIndexers sets up field indexers for Gateway references.
func setupGatewayIndexers(ctx context.Context, mgr manager.Manager) error {
	indexer := mgr.GetFieldIndexer()

	// Index HTTPRoutes by Gateway reference
	httpRouteIndexFunc := func(obj client.Object) []string {
		route := obj.(*avapigwv1alpha1.HTTPRoute)
		return extractGatewayRefs(route.Namespace, route.Spec.ParentRefs)
	}
	err := indexer.IndexField(ctx, &avapigwv1alpha1.HTTPRoute{}, HTTPRouteGatewayIndexField, httpRouteIndexFunc)
	if err != nil {
		return err
	}

	// Index GRPCRoutes by Gateway reference
	grpcRouteIndexFunc := func(obj client.Object) []string {
		route := obj.(*avapigwv1alpha1.GRPCRoute)
		return extractGatewayRefs(route.Namespace, route.Spec.ParentRefs)
	}
	err = indexer.IndexField(ctx, &avapigwv1alpha1.GRPCRoute{}, GRPCRouteGatewayIndexField, grpcRouteIndexFunc)
	if err != nil {
		return err
	}

	// Index TCPRoutes by Gateway reference
	tcpRouteIndexFunc := func(obj client.Object) []string {
		route := obj.(*avapigwv1alpha1.TCPRoute)
		return extractGatewayRefs(route.Namespace, route.Spec.ParentRefs)
	}
	err = indexer.IndexField(ctx, &avapigwv1alpha1.TCPRoute{}, TCPRouteGatewayIndexField, tcpRouteIndexFunc)
	if err != nil {
		return err
	}

	// Index TLSRoutes by Gateway reference
	tlsRouteIndexFunc := func(obj client.Object) []string {
		route := obj.(*avapigwv1alpha1.TLSRoute)
		return extractGatewayRefs(route.Namespace, route.Spec.ParentRefs)
	}
	return indexer.IndexField(ctx, &avapigwv1alpha1.TLSRoute{}, TLSRouteGatewayIndexField, tlsRouteIndexFunc)
}

// setupBackendIndexers sets up field indexers for Backend references.
func setupBackendIndexers(ctx context.Context, mgr manager.Manager) error {
	indexer := mgr.GetFieldIndexer()

	// Index HTTPRoutes by Backend reference
	httpRouteBackendIndexFunc := func(obj client.Object) []string {
		route := obj.(*avapigwv1alpha1.HTTPRoute)
		return extractHTTPBackendRefs(route.Namespace, route.Spec.Rules)
	}
	err := indexer.IndexField(ctx, &avapigwv1alpha1.HTTPRoute{}, HTTPRouteBackendIndexField, httpRouteBackendIndexFunc)
	if err != nil {
		return err
	}

	// Index GRPCRoutes by Backend reference
	grpcRouteBackendIndexFunc := func(obj client.Object) []string {
		route := obj.(*avapigwv1alpha1.GRPCRoute)
		return extractGRPCBackendRefs(route.Namespace, route.Spec.Rules)
	}
	err = indexer.IndexField(ctx, &avapigwv1alpha1.GRPCRoute{}, GRPCRouteBackendIndexField, grpcRouteBackendIndexFunc)
	if err != nil {
		return err
	}

	// Index TCPRoutes by Backend reference
	tcpRouteBackendIndexFunc := func(obj client.Object) []string {
		route := obj.(*avapigwv1alpha1.TCPRoute)
		return extractTCPBackendRefs(route.Namespace, route.Spec.Rules)
	}
	err = indexer.IndexField(ctx, &avapigwv1alpha1.TCPRoute{}, TCPRouteBackendIndexField, tcpRouteBackendIndexFunc)
	if err != nil {
		return err
	}

	// Index TLSRoutes by Backend reference
	tlsRouteBackendIndexFunc := func(obj client.Object) []string {
		route := obj.(*avapigwv1alpha1.TLSRoute)
		return extractTLSBackendRefs(route.Namespace, route.Spec.Rules)
	}
	return indexer.IndexField(ctx, &avapigwv1alpha1.TLSRoute{}, TLSRouteBackendIndexField, tlsRouteBackendIndexFunc)
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

// extractHTTPBackendRefs extracts backend references from HTTP route rules.
// Returns a list of "namespace/name" strings for indexing.
func extractHTTPBackendRefs(routeNamespace string, rules []avapigwv1alpha1.HTTPRouteRule) []string {
	var refs []string
	for _, rule := range rules {
		for _, backendRef := range rule.BackendRefs {
			namespace := routeNamespace
			if backendRef.Namespace != nil {
				namespace = *backendRef.Namespace
			}
			kind := BackendKindService
			if backendRef.Kind != nil {
				kind = *backendRef.Kind
			}
			// Only index Backend kind references
			if kind == BackendKindBackend {
				refs = append(refs, namespace+"/"+backendRef.Name)
			}
		}
	}
	return refs
}

// extractGRPCBackendRefs extracts backend references from GRPC route rules.
// Returns a list of "namespace/name" strings for indexing.
func extractGRPCBackendRefs(routeNamespace string, rules []avapigwv1alpha1.GRPCRouteRule) []string {
	var refs []string
	for _, rule := range rules {
		for _, backendRef := range rule.BackendRefs {
			namespace := routeNamespace
			if backendRef.Namespace != nil {
				namespace = *backendRef.Namespace
			}
			kind := BackendKindService
			if backendRef.Kind != nil {
				kind = *backendRef.Kind
			}
			// Only index Backend kind references
			if kind == BackendKindBackend {
				refs = append(refs, namespace+"/"+backendRef.Name)
			}
		}
	}
	return refs
}

// extractTCPBackendRefs extracts backend references from TCP route rules.
// Returns a list of "namespace/name" strings for indexing.
func extractTCPBackendRefs(routeNamespace string, rules []avapigwv1alpha1.TCPRouteRule) []string {
	var refs []string
	for _, rule := range rules {
		for _, backendRef := range rule.BackendRefs {
			namespace := routeNamespace
			if backendRef.Namespace != nil {
				namespace = *backendRef.Namespace
			}
			kind := BackendKindService
			if backendRef.Kind != nil {
				kind = *backendRef.Kind
			}
			// Only index Backend kind references
			if kind == BackendKindBackend {
				refs = append(refs, namespace+"/"+backendRef.Name)
			}
		}
	}
	return refs
}

// extractTLSBackendRefs extracts backend references from TLS route rules.
// Returns a list of "namespace/name" strings for indexing.
func extractTLSBackendRefs(routeNamespace string, rules []avapigwv1alpha1.TLSRouteRule) []string {
	var refs []string
	for _, rule := range rules {
		for _, backendRef := range rule.BackendRefs {
			namespace := routeNamespace
			if backendRef.Namespace != nil {
				namespace = *backendRef.Namespace
			}
			kind := BackendKindService
			if backendRef.Kind != nil {
				kind = *backendRef.Kind
			}
			// Only index Backend kind references
			if kind == BackendKindBackend {
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
