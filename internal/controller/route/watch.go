// Package route provides shared utilities for route controllers.
package route

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

// RouteList is an interface for route list types.
type RouteList interface {
	client.ObjectList
	GetItems() []client.Object
}

// WatchHandler provides generic watch handler utilities for route controllers.
// It uses field indexers for efficient lookups instead of full list scans.
type WatchHandler struct {
	Client            client.Client
	GatewayIndexField string
	BackendIndexField string
}

// NewWatchHandler creates a new WatchHandler.
func NewWatchHandler(c client.Client, gatewayIndexField, backendIndexField string) *WatchHandler {
	return &WatchHandler{
		Client:            c,
		GatewayIndexField: gatewayIndexField,
		BackendIndexField: backendIndexField,
	}
}

// FindHTTPRoutesForGateway finds HTTPRoutes that reference a Gateway using field indexers.
func (h *WatchHandler) FindHTTPRoutesForGateway(
	ctx context.Context,
	gateway *avapigwv1alpha1.Gateway,
) []reconcile.Request {
	logger := log.FromContext(ctx)

	// Use field index for efficient lookup
	gatewayKey := GatewayIndexKey(gateway.Namespace, gateway.Name)
	var routes avapigwv1alpha1.HTTPRouteList
	if err := h.Client.List(ctx, &routes, client.MatchingFields{h.GatewayIndexField: gatewayKey}); err != nil {
		logger.Error(err, "Failed to list HTTPRoutes for Gateway",
			"gateway", gateway.Name,
			"namespace", gateway.Namespace,
		)
		return nil
	}

	return buildReconcileRequests(routes.Items)
}

// FindHTTPRoutesForBackend finds HTTPRoutes that reference a Backend using field indexers.
func (h *WatchHandler) FindHTTPRoutesForBackend(
	ctx context.Context,
	backend *avapigwv1alpha1.Backend,
) []reconcile.Request {
	logger := log.FromContext(ctx)

	// Use field index for efficient lookup
	backendKey := BackendIndexKey(backend.Namespace, backend.Name)
	var routes avapigwv1alpha1.HTTPRouteList
	if err := h.Client.List(ctx, &routes, client.MatchingFields{h.BackendIndexField: backendKey}); err != nil {
		logger.Error(err, "Failed to list HTTPRoutes for Backend",
			"backend", backend.Name,
			"namespace", backend.Namespace,
		)
		return nil
	}

	return buildReconcileRequests(routes.Items)
}

// FindGRPCRoutesForGateway finds GRPCRoutes that reference a Gateway using field indexers.
func (h *WatchHandler) FindGRPCRoutesForGateway(
	ctx context.Context,
	gateway *avapigwv1alpha1.Gateway,
) []reconcile.Request {
	logger := log.FromContext(ctx)

	// Use field index for efficient lookup
	gatewayKey := GatewayIndexKey(gateway.Namespace, gateway.Name)
	var routes avapigwv1alpha1.GRPCRouteList
	if err := h.Client.List(ctx, &routes, client.MatchingFields{h.GatewayIndexField: gatewayKey}); err != nil {
		logger.Error(err, "Failed to list GRPCRoutes for Gateway",
			"gateway", gateway.Name,
			"namespace", gateway.Namespace,
		)
		return nil
	}

	return buildGRPCReconcileRequests(routes.Items)
}

// FindGRPCRoutesForBackend finds GRPCRoutes that reference a Backend using field indexers.
func (h *WatchHandler) FindGRPCRoutesForBackend(
	ctx context.Context,
	backend *avapigwv1alpha1.Backend,
) []reconcile.Request {
	logger := log.FromContext(ctx)

	// Use field index for efficient lookup
	backendKey := BackendIndexKey(backend.Namespace, backend.Name)
	var routes avapigwv1alpha1.GRPCRouteList
	if err := h.Client.List(ctx, &routes, client.MatchingFields{h.BackendIndexField: backendKey}); err != nil {
		logger.Error(err, "Failed to list GRPCRoutes for Backend",
			"backend", backend.Name,
			"namespace", backend.Namespace,
		)
		return nil
	}

	return buildGRPCReconcileRequests(routes.Items)
}

// FindTCPRoutesForGateway finds TCPRoutes that reference a Gateway using field indexers.
func (h *WatchHandler) FindTCPRoutesForGateway(
	ctx context.Context,
	gateway *avapigwv1alpha1.Gateway,
) []reconcile.Request {
	logger := log.FromContext(ctx)

	// Use field index for efficient lookup
	gatewayKey := GatewayIndexKey(gateway.Namespace, gateway.Name)
	var routes avapigwv1alpha1.TCPRouteList
	if err := h.Client.List(ctx, &routes, client.MatchingFields{h.GatewayIndexField: gatewayKey}); err != nil {
		logger.Error(err, "Failed to list TCPRoutes for Gateway",
			"gateway", gateway.Name,
			"namespace", gateway.Namespace,
		)
		return nil
	}

	return buildTCPReconcileRequests(routes.Items)
}

// FindTCPRoutesForBackend finds TCPRoutes that reference a Backend using field indexers.
func (h *WatchHandler) FindTCPRoutesForBackend(
	ctx context.Context,
	backend *avapigwv1alpha1.Backend,
) []reconcile.Request {
	logger := log.FromContext(ctx)

	// Use field index for efficient lookup
	backendKey := BackendIndexKey(backend.Namespace, backend.Name)
	var routes avapigwv1alpha1.TCPRouteList
	if err := h.Client.List(ctx, &routes, client.MatchingFields{h.BackendIndexField: backendKey}); err != nil {
		logger.Error(err, "Failed to list TCPRoutes for Backend",
			"backend", backend.Name,
			"namespace", backend.Namespace,
		)
		return nil
	}

	return buildTCPReconcileRequests(routes.Items)
}

// FindTLSRoutesForGateway finds TLSRoutes that reference a Gateway using field indexers.
func (h *WatchHandler) FindTLSRoutesForGateway(
	ctx context.Context,
	gateway *avapigwv1alpha1.Gateway,
) []reconcile.Request {
	logger := log.FromContext(ctx)

	// Use field index for efficient lookup
	gatewayKey := GatewayIndexKey(gateway.Namespace, gateway.Name)
	var routes avapigwv1alpha1.TLSRouteList
	if err := h.Client.List(ctx, &routes, client.MatchingFields{h.GatewayIndexField: gatewayKey}); err != nil {
		logger.Error(err, "Failed to list TLSRoutes for Gateway",
			"gateway", gateway.Name,
			"namespace", gateway.Namespace,
		)
		return nil
	}

	return buildTLSReconcileRequests(routes.Items)
}

// FindTLSRoutesForBackend finds TLSRoutes that reference a Backend using field indexers.
func (h *WatchHandler) FindTLSRoutesForBackend(
	ctx context.Context,
	backend *avapigwv1alpha1.Backend,
) []reconcile.Request {
	logger := log.FromContext(ctx)

	// Use field index for efficient lookup
	backendKey := BackendIndexKey(backend.Namespace, backend.Name)
	var routes avapigwv1alpha1.TLSRouteList
	if err := h.Client.List(ctx, &routes, client.MatchingFields{h.BackendIndexField: backendKey}); err != nil {
		logger.Error(err, "Failed to list TLSRoutes for Backend",
			"backend", backend.Name,
			"namespace", backend.Namespace,
		)
		return nil
	}

	return buildTLSReconcileRequests(routes.Items)
}

// GatewayIndexKey returns the index key for a gateway.
func GatewayIndexKey(namespace, name string) string {
	return namespace + "/" + name
}

// BackendIndexKey returns the index key for a backend.
func BackendIndexKey(namespace, name string) string {
	return namespace + "/" + name
}

// buildReconcileRequests builds reconcile requests from HTTPRoute items.
func buildReconcileRequests(items []avapigwv1alpha1.HTTPRoute) []reconcile.Request {
	requests := make([]reconcile.Request, 0, len(items))
	for _, route := range items {
		requests = append(requests, reconcile.Request{
			NamespacedName: client.ObjectKey{
				Namespace: route.Namespace,
				Name:      route.Name,
			},
		})
	}
	return requests
}

// buildGRPCReconcileRequests builds reconcile requests from GRPCRoute items.
func buildGRPCReconcileRequests(items []avapigwv1alpha1.GRPCRoute) []reconcile.Request {
	requests := make([]reconcile.Request, 0, len(items))
	for _, route := range items {
		requests = append(requests, reconcile.Request{
			NamespacedName: client.ObjectKey{
				Namespace: route.Namespace,
				Name:      route.Name,
			},
		})
	}
	return requests
}

// buildTCPReconcileRequests builds reconcile requests from TCPRoute items.
func buildTCPReconcileRequests(items []avapigwv1alpha1.TCPRoute) []reconcile.Request {
	requests := make([]reconcile.Request, 0, len(items))
	for _, route := range items {
		requests = append(requests, reconcile.Request{
			NamespacedName: client.ObjectKey{
				Namespace: route.Namespace,
				Name:      route.Name,
			},
		})
	}
	return requests
}

// buildTLSReconcileRequests builds reconcile requests from TLSRoute items.
func buildTLSReconcileRequests(items []avapigwv1alpha1.TLSRoute) []reconcile.Request {
	requests := make([]reconcile.Request, 0, len(items))
	for _, route := range items {
		requests = append(requests, reconcile.Request{
			NamespacedName: client.ObjectKey{
				Namespace: route.Namespace,
				Name:      route.Name,
			},
		})
	}
	return requests
}
