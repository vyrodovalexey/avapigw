// Copyright 2026 The avapigw Authors.
// SPDX-License-Identifier: Apache-2.0

package operator

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	operatorv1alpha1 "github.com/vyrodovalexey/avapigw/proto/operator/v1alpha1"
)

// ConfigApplier is the interface for applying configuration changes.
type ConfigApplier interface {
	// ApplyRoutes applies HTTP route configuration.
	ApplyRoutes(ctx context.Context, routes []config.Route) error

	// ApplyBackends applies HTTP backend configuration.
	ApplyBackends(ctx context.Context, backends []config.Backend) error

	// ApplyGRPCRoutes applies gRPC route configuration.
	ApplyGRPCRoutes(ctx context.Context, routes []config.GRPCRoute) error

	// ApplyGRPCBackends applies gRPC backend configuration.
	ApplyGRPCBackends(ctx context.Context, backends []config.GRPCBackend) error

	// ApplyFullConfig applies a complete configuration.
	ApplyFullConfig(ctx context.Context, cfg *config.GatewayConfig) error
}

// ConfigHandler handles configuration updates from the operator.
type ConfigHandler struct {
	applier          ConfigApplier
	logger           observability.Logger
	tracer           trace.Tracer
	cacheInvalidator CacheInvalidator

	// Current state tracking
	mu           sync.RWMutex
	routes       map[string]*config.Route       // key: namespace/name
	backends     map[string]*config.Backend     // key: namespace/name
	grpcRoutes   map[string]*config.GRPCRoute   // key: namespace/name
	grpcBackends map[string]*config.GRPCBackend // key: namespace/name
}

// CacheInvalidator is called when configuration changes require cache invalidation.
type CacheInvalidator func()

// ConfigHandlerOption is a functional option for ConfigHandler.
type ConfigHandlerOption func(*ConfigHandler)

// WithHandlerLogger sets the logger for the handler.
func WithHandlerLogger(logger observability.Logger) ConfigHandlerOption {
	return func(h *ConfigHandler) {
		h.logger = logger
	}
}

// WithHandlerTracer sets the tracer for the handler.
func WithHandlerTracer(tracer trace.Tracer) ConfigHandlerOption {
	return func(h *ConfigHandler) {
		h.tracer = tracer
	}
}

// WithCacheInvalidator sets the cache invalidation callback.
// This is called whenever configuration changes are applied, allowing
// the route middleware cache to be cleared.
func WithCacheInvalidator(invalidator CacheInvalidator) ConfigHandlerOption {
	return func(h *ConfigHandler) {
		h.cacheInvalidator = invalidator
	}
}

// NewConfigHandler creates a new ConfigHandler.
func NewConfigHandler(applier ConfigApplier, opts ...ConfigHandlerOption) *ConfigHandler {
	h := &ConfigHandler{
		applier:      applier,
		logger:       observability.NopLogger(),
		tracer:       otel.Tracer("config-handler"),
		routes:       make(map[string]*config.Route),
		backends:     make(map[string]*config.Backend),
		grpcRoutes:   make(map[string]*config.GRPCRoute),
		grpcBackends: make(map[string]*config.GRPCBackend),
	}

	for _, opt := range opts {
		opt(h)
	}

	return h
}

// HandleUpdate processes a configuration update.
func (h *ConfigHandler) HandleUpdate(ctx context.Context, update *operatorv1alpha1.ConfigurationUpdate) error {
	ctx, span := h.tracer.Start(ctx, "ConfigHandler.HandleUpdate",
		trace.WithAttributes(
			attribute.String("update.type", update.Type.String()),
			attribute.String("update.version", update.Version),
		),
	)
	defer span.End()

	if update.Resource == nil {
		h.logger.Debug("received update without resource, skipping")
		return nil
	}

	resource := update.Resource
	key := resourceKey(resource.Namespace, resource.Name)

	h.logger.Info("handling configuration update",
		observability.String("type", update.Type.String()),
		observability.String("resource_type", resource.Type.String()),
		observability.String("resource_name", resource.Name),
		observability.String("resource_namespace", resource.Namespace),
	)

	switch update.Type {
	case operatorv1alpha1.UpdateType_UPDATE_TYPE_ADDED, operatorv1alpha1.UpdateType_UPDATE_TYPE_MODIFIED:
		return h.handleAddOrModify(ctx, resource, key)
	case operatorv1alpha1.UpdateType_UPDATE_TYPE_DELETED:
		return h.handleDelete(ctx, resource, key)
	case operatorv1alpha1.UpdateType_UPDATE_TYPE_FULL_SYNC:
		if update.Snapshot != nil {
			return h.HandleSnapshot(ctx, update.Snapshot)
		}
	default:
		h.logger.Debug("ignoring update type",
			observability.String("type", update.Type.String()),
		)
	}

	return nil
}

// handleAddOrModify handles resource addition or modification.
func (h *ConfigHandler) handleAddOrModify(
	ctx context.Context, resource *operatorv1alpha1.ConfigurationResource, key string,
) error {
	switch resource.Type {
	case operatorv1alpha1.ResourceType_RESOURCE_TYPE_API_ROUTE:
		return h.handleRouteUpdate(ctx, resource, key)
	case operatorv1alpha1.ResourceType_RESOURCE_TYPE_BACKEND:
		return h.handleBackendUpdate(ctx, resource, key)
	case operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRPC_ROUTE:
		return h.handleGRPCRouteUpdate(ctx, resource, key)
	case operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRPC_BACKEND:
		return h.handleGRPCBackendUpdate(ctx, resource, key)
	default:
		h.logger.Warn("unknown resource type",
			observability.String("type", resource.Type.String()),
		)
	}
	return nil
}

// handleDelete handles resource deletion.
func (h *ConfigHandler) handleDelete(
	ctx context.Context, resource *operatorv1alpha1.ConfigurationResource, key string,
) error {
	switch resource.Type {
	case operatorv1alpha1.ResourceType_RESOURCE_TYPE_API_ROUTE:
		return h.handleRouteDelete(ctx, key)
	case operatorv1alpha1.ResourceType_RESOURCE_TYPE_BACKEND:
		return h.handleBackendDelete(ctx, key)
	case operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRPC_ROUTE:
		return h.handleGRPCRouteDelete(ctx, key)
	case operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRPC_BACKEND:
		return h.handleGRPCBackendDelete(ctx, key)
	default:
		h.logger.Warn("unknown resource type for deletion",
			observability.String("type", resource.Type.String()),
		)
	}
	return nil
}

// handleRouteUpdate handles HTTP route updates.
func (h *ConfigHandler) handleRouteUpdate(
	ctx context.Context, resource *operatorv1alpha1.ConfigurationResource, key string,
) error {
	var route config.Route
	if err := json.Unmarshal(resource.SpecJson, &route); err != nil {
		return fmt.Errorf("failed to unmarshal route spec: %w", err)
	}

	h.mu.Lock()
	h.routes[key] = &route
	routes := h.collectRoutes()
	h.mu.Unlock()

	if h.applier != nil {
		if err := h.applier.ApplyRoutes(ctx, routes); err != nil {
			return fmt.Errorf("failed to apply routes: %w", err)
		}
	}

	h.invalidateCache()

	h.logger.Info("route updated",
		observability.String("name", route.Name),
		observability.String("key", key),
	)

	return nil
}

// handleRouteDelete handles HTTP route deletion.
func (h *ConfigHandler) handleRouteDelete(ctx context.Context, key string) error {
	h.mu.Lock()
	delete(h.routes, key)
	routes := h.collectRoutes()
	h.mu.Unlock()

	if h.applier != nil {
		if err := h.applier.ApplyRoutes(ctx, routes); err != nil {
			return fmt.Errorf("failed to apply routes after deletion: %w", err)
		}
	}

	h.invalidateCache()

	h.logger.Info("route deleted",
		observability.String("key", key),
	)

	return nil
}

// handleBackendUpdate handles HTTP backend updates.
func (h *ConfigHandler) handleBackendUpdate(
	ctx context.Context, resource *operatorv1alpha1.ConfigurationResource, key string,
) error {
	var backend config.Backend
	if err := json.Unmarshal(resource.SpecJson, &backend); err != nil {
		return fmt.Errorf("failed to unmarshal backend spec: %w", err)
	}

	h.mu.Lock()
	h.backends[key] = &backend
	backends := h.collectBackends()
	h.mu.Unlock()

	if h.applier != nil {
		if err := h.applier.ApplyBackends(ctx, backends); err != nil {
			return fmt.Errorf("failed to apply backends: %w", err)
		}
	}

	h.invalidateCache()

	h.logger.Info("backend updated",
		observability.String("name", backend.Name),
		observability.String("key", key),
	)

	return nil
}

// handleBackendDelete handles HTTP backend deletion.
func (h *ConfigHandler) handleBackendDelete(ctx context.Context, key string) error {
	h.mu.Lock()
	delete(h.backends, key)
	backends := h.collectBackends()
	h.mu.Unlock()

	if h.applier != nil {
		if err := h.applier.ApplyBackends(ctx, backends); err != nil {
			return fmt.Errorf("failed to apply backends after deletion: %w", err)
		}
	}

	h.invalidateCache()

	h.logger.Info("backend deleted",
		observability.String("key", key),
	)

	return nil
}

// handleGRPCRouteUpdate handles gRPC route updates.
func (h *ConfigHandler) handleGRPCRouteUpdate(
	ctx context.Context, resource *operatorv1alpha1.ConfigurationResource, key string,
) error {
	var route config.GRPCRoute
	if err := json.Unmarshal(resource.SpecJson, &route); err != nil {
		return fmt.Errorf("failed to unmarshal gRPC route spec: %w", err)
	}

	h.mu.Lock()
	h.grpcRoutes[key] = &route
	routes := h.collectGRPCRoutes()
	h.mu.Unlock()

	if h.applier != nil {
		if err := h.applier.ApplyGRPCRoutes(ctx, routes); err != nil {
			return fmt.Errorf("failed to apply gRPC routes: %w", err)
		}
	}

	h.invalidateCache()

	h.logger.Info("gRPC route updated",
		observability.String("name", route.Name),
		observability.String("key", key),
	)

	return nil
}

// handleGRPCRouteDelete handles gRPC route deletion.
func (h *ConfigHandler) handleGRPCRouteDelete(ctx context.Context, key string) error {
	h.mu.Lock()
	delete(h.grpcRoutes, key)
	routes := h.collectGRPCRoutes()
	h.mu.Unlock()

	if h.applier != nil {
		if err := h.applier.ApplyGRPCRoutes(ctx, routes); err != nil {
			return fmt.Errorf("failed to apply gRPC routes after deletion: %w", err)
		}
	}

	h.invalidateCache()

	h.logger.Info("gRPC route deleted",
		observability.String("key", key),
	)

	return nil
}

// handleGRPCBackendUpdate handles gRPC backend updates.
func (h *ConfigHandler) handleGRPCBackendUpdate(
	ctx context.Context, resource *operatorv1alpha1.ConfigurationResource, key string,
) error {
	var backend config.GRPCBackend
	if err := json.Unmarshal(resource.SpecJson, &backend); err != nil {
		return fmt.Errorf("failed to unmarshal gRPC backend spec: %w", err)
	}

	h.mu.Lock()
	h.grpcBackends[key] = &backend
	backends := h.collectGRPCBackends()
	h.mu.Unlock()

	if h.applier != nil {
		if err := h.applier.ApplyGRPCBackends(ctx, backends); err != nil {
			return fmt.Errorf("failed to apply gRPC backends: %w", err)
		}
	}

	h.invalidateCache()

	h.logger.Info("gRPC backend updated",
		observability.String("name", backend.Name),
		observability.String("key", key),
	)

	return nil
}

// handleGRPCBackendDelete handles gRPC backend deletion.
func (h *ConfigHandler) handleGRPCBackendDelete(ctx context.Context, key string) error {
	h.mu.Lock()
	delete(h.grpcBackends, key)
	backends := h.collectGRPCBackends()
	h.mu.Unlock()

	if h.applier != nil {
		if err := h.applier.ApplyGRPCBackends(ctx, backends); err != nil {
			return fmt.Errorf("failed to apply gRPC backends after deletion: %w", err)
		}
	}

	h.invalidateCache()

	h.logger.Info("gRPC backend deleted",
		observability.String("key", key),
	)

	return nil
}

// HandleSnapshot applies a full configuration snapshot.
func (h *ConfigHandler) HandleSnapshot(ctx context.Context, snapshot *operatorv1alpha1.ConfigurationSnapshot) error {
	ctx, span := h.tracer.Start(ctx, "ConfigHandler.HandleSnapshot",
		trace.WithAttributes(
			attribute.String("snapshot.version", snapshot.Version),
			attribute.Int("snapshot.total_resources", int(snapshot.TotalResources)),
		),
	)
	defer span.End()

	h.logger.Info("applying configuration snapshot",
		observability.String("version", snapshot.Version),
		observability.Int("total_resources", int(snapshot.TotalResources)),
	)

	// Clear existing state
	h.mu.Lock()
	h.routes = make(map[string]*config.Route)
	h.backends = make(map[string]*config.Backend)
	h.grpcRoutes = make(map[string]*config.GRPCRoute)
	h.grpcBackends = make(map[string]*config.GRPCBackend)
	h.mu.Unlock()

	// Process API routes
	routes := h.parseRoutes(snapshot.ApiRoutes)

	// Process backends
	backends := h.parseBackends(snapshot.Backends)

	// Process gRPC routes
	grpcRoutes := h.parseGRPCRoutes(snapshot.GrpcRoutes)

	// Process gRPC backends
	grpcBackends := h.parseGRPCBackends(snapshot.GrpcBackends)

	// Store in state
	h.mu.Lock()
	for _, r := range routes {
		route := r
		key := resourceKey("", route.Name)
		h.routes[key] = &route
	}
	for _, b := range backends {
		backend := b
		key := resourceKey("", backend.Name)
		h.backends[key] = &backend
	}
	for _, r := range grpcRoutes {
		route := r
		key := resourceKey("", route.Name)
		h.grpcRoutes[key] = &route
	}
	for _, b := range grpcBackends {
		backend := b
		key := resourceKey("", backend.Name)
		h.grpcBackends[key] = &backend
	}
	h.mu.Unlock()

	// Apply full configuration if applier supports it
	if h.applier != nil {
		cfg := &config.GatewayConfig{
			Spec: config.GatewaySpec{
				Routes:       routes,
				Backends:     backends,
				GRPCRoutes:   grpcRoutes,
				GRPCBackends: grpcBackends,
			},
		}

		if err := h.applier.ApplyFullConfig(ctx, cfg); err != nil {
			return fmt.Errorf("failed to apply full configuration: %w", err)
		}
	}

	h.invalidateCache()

	h.logger.Info("configuration snapshot applied",
		observability.String("version", snapshot.Version),
		observability.Int("routes", len(routes)),
		observability.Int("backends", len(backends)),
		observability.Int("grpc_routes", len(grpcRoutes)),
		observability.Int("grpc_backends", len(grpcBackends)),
	)

	return nil
}

// parseRoutes parses configuration resources into routes.
func (h *ConfigHandler) parseRoutes(
	resources []*operatorv1alpha1.ConfigurationResource,
) []config.Route {
	routes := make([]config.Route, 0, len(resources))
	for _, r := range resources {
		var route config.Route
		if err := json.Unmarshal(r.SpecJson, &route); err != nil {
			h.logger.Error("failed to parse route",
				observability.String("name", r.Name),
				observability.Error(err),
			)
			continue
		}
		routes = append(routes, route)
	}
	return routes
}

// parseBackends parses configuration resources into backends.
func (h *ConfigHandler) parseBackends(
	resources []*operatorv1alpha1.ConfigurationResource,
) []config.Backend {
	backends := make([]config.Backend, 0, len(resources))
	for _, r := range resources {
		var backend config.Backend
		if err := json.Unmarshal(r.SpecJson, &backend); err != nil {
			h.logger.Error("failed to parse backend",
				observability.String("name", r.Name),
				observability.Error(err),
			)
			continue
		}
		backends = append(backends, backend)
	}
	return backends
}

// parseGRPCRoutes parses configuration resources into gRPC routes.
func (h *ConfigHandler) parseGRPCRoutes(
	resources []*operatorv1alpha1.ConfigurationResource,
) []config.GRPCRoute {
	routes := make([]config.GRPCRoute, 0, len(resources))
	for _, r := range resources {
		var route config.GRPCRoute
		if err := json.Unmarshal(r.SpecJson, &route); err != nil {
			h.logger.Error("failed to parse gRPC route",
				observability.String("name", r.Name),
				observability.Error(err),
			)
			continue
		}
		routes = append(routes, route)
	}
	return routes
}

// parseGRPCBackends parses configuration resources into gRPC backends.
func (h *ConfigHandler) parseGRPCBackends(
	resources []*operatorv1alpha1.ConfigurationResource,
) []config.GRPCBackend {
	backends := make([]config.GRPCBackend, 0, len(resources))
	for _, r := range resources {
		var backend config.GRPCBackend
		if err := json.Unmarshal(r.SpecJson, &backend); err != nil {
			h.logger.Error("failed to parse gRPC backend",
				observability.String("name", r.Name),
				observability.Error(err),
			)
			continue
		}
		backends = append(backends, backend)
	}
	return backends
}

// collectRoutes collects all routes from the state.
func (h *ConfigHandler) collectRoutes() []config.Route {
	routes := make([]config.Route, 0, len(h.routes))
	for _, r := range h.routes {
		routes = append(routes, *r)
	}
	return routes
}

// collectBackends collects all backends from the state.
func (h *ConfigHandler) collectBackends() []config.Backend {
	backends := make([]config.Backend, 0, len(h.backends))
	for _, b := range h.backends {
		backends = append(backends, *b)
	}
	return backends
}

// collectGRPCRoutes collects all gRPC routes from the state.
func (h *ConfigHandler) collectGRPCRoutes() []config.GRPCRoute {
	routes := make([]config.GRPCRoute, 0, len(h.grpcRoutes))
	for _, r := range h.grpcRoutes {
		routes = append(routes, *r)
	}
	return routes
}

// collectGRPCBackends collects all gRPC backends from the state.
func (h *ConfigHandler) collectGRPCBackends() []config.GRPCBackend {
	backends := make([]config.GRPCBackend, 0, len(h.grpcBackends))
	for _, b := range h.grpcBackends {
		backends = append(backends, *b)
	}
	return backends
}

// invalidateCache calls the cache invalidation callback if configured.
// This should be called after any configuration change is applied.
func (h *ConfigHandler) invalidateCache() {
	if h.cacheInvalidator != nil {
		h.cacheInvalidator()
		h.logger.Debug("route middleware cache invalidated after config change")
	}
}

// resourceKey creates a unique key for a resource.
func resourceKey(namespace, name string) string {
	if namespace == "" {
		return name
	}
	return namespace + "/" + name
}

// GetCurrentState returns the current configuration state.
func (h *ConfigHandler) GetCurrentState() (
	routes []config.Route,
	backends []config.Backend,
	grpcRoutes []config.GRPCRoute,
	grpcBackends []config.GRPCBackend,
) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return h.collectRoutes(), h.collectBackends(), h.collectGRPCRoutes(), h.collectGRPCBackends()
}
