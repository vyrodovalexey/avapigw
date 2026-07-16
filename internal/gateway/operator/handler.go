// Copyright 2026 The avapigw Authors.
// SPDX-License-Identifier: Apache-2.0

package operator

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/vyrodovalexey/avapigw/internal/config"
	graphqlrouter "github.com/vyrodovalexey/avapigw/internal/graphql/router"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	operatorv1alpha1 "github.com/vyrodovalexey/avapigw/proto/operator/v1alpha1"
)

// snapshotRegressionWindow is the post-(re)connect stabilization window
// during which FULL_SYNC snapshots whose resource count REGRESSES versus the
// running configuration are deferred instead of applied. Right after an
// operator restart the store may still be mid-seed, and applying its partial
// snapshots shrinks the route set (observed live as ~30s of 404s while
// routes dropped 25→3→11→25). Growing snapshots are always applied, and a
// genuine shrink is honored once the window has passed.
const snapshotRegressionWindow = 30 * time.Second

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

	// ApplyGraphQLRoutes applies GraphQL route configuration.
	ApplyGraphQLRoutes(ctx context.Context, routes []config.GraphQLRoute) error

	// ApplyGraphQLBackends applies GraphQL backend configuration.
	ApplyGraphQLBackends(ctx context.Context, backends []config.GraphQLBackend) error

	// ApplyFullConfig applies a complete configuration.
	ApplyFullConfig(ctx context.Context, cfg *config.GatewayConfig) error
}

// ConfigHandler handles configuration updates from the operator.
type ConfigHandler struct {
	applier          ConfigApplier
	logger           observability.Logger
	tracer           trace.Tracer
	cacheInvalidator CacheInvalidator

	// reconnectedAt holds the UnixNano timestamp of the most recent operator
	// (re)connect (see MarkReconnected). Zero means no reconnect was ever
	// signaled, which disables the snapshot regression window entirely.
	reconnectedAt atomic.Int64

	// Current state tracking
	mu              sync.RWMutex
	routes          map[string]*config.Route          // key: namespace/name
	backends        map[string]*config.Backend        // key: namespace/name
	grpcRoutes      map[string]*config.GRPCRoute      // key: namespace/name
	grpcBackends    map[string]*config.GRPCBackend    // key: namespace/name
	graphqlRoutes   map[string]*config.GraphQLRoute   // key: namespace/name
	graphqlBackends map[string]*config.GraphQLBackend // key: namespace/name
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
		applier:         applier,
		logger:          observability.NopLogger(),
		tracer:          otel.Tracer("config-handler"),
		routes:          make(map[string]*config.Route),
		backends:        make(map[string]*config.Backend),
		grpcRoutes:      make(map[string]*config.GRPCRoute),
		grpcBackends:    make(map[string]*config.GRPCBackend),
		graphqlRoutes:   make(map[string]*config.GraphQLRoute),
		graphqlBackends: make(map[string]*config.GraphQLBackend),
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
	case operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRAPHQL_ROUTE:
		return h.handleGraphQLRouteUpdate(ctx, resource, key)
	case operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRAPHQL_BACKEND:
		return h.handleGraphQLBackendUpdate(ctx, resource, key)
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
	case operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRAPHQL_ROUTE:
		return h.handleGraphQLRouteDelete(ctx, key)
	case operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRAPHQL_BACKEND:
		return h.handleGraphQLBackendDelete(ctx, key)
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

// handleGraphQLRouteUpdate handles GraphQL route updates.
func (h *ConfigHandler) handleGraphQLRouteUpdate(
	ctx context.Context, resource *operatorv1alpha1.ConfigurationResource, key string,
) error {
	var route config.GraphQLRoute
	if err := json.Unmarshal(resource.SpecJson, &route); err != nil {
		return fmt.Errorf("failed to unmarshal GraphQL route spec: %w", err)
	}

	h.mu.Lock()
	h.graphqlRoutes[key] = &route
	routes := h.collectGraphQLRoutes()
	h.mu.Unlock()

	if h.applier != nil {
		if err := h.applier.ApplyGraphQLRoutes(ctx, routes); err != nil {
			return fmt.Errorf("failed to apply GraphQL routes: %w", err)
		}
	}

	h.invalidateCache()

	h.logger.Info("GraphQL route updated",
		observability.String("name", route.Name),
		observability.String("key", key),
	)

	return nil
}

// handleGraphQLRouteDelete handles GraphQL route deletion.
func (h *ConfigHandler) handleGraphQLRouteDelete(ctx context.Context, key string) error {
	h.mu.Lock()
	delete(h.graphqlRoutes, key)
	routes := h.collectGraphQLRoutes()
	h.mu.Unlock()

	if h.applier != nil {
		if err := h.applier.ApplyGraphQLRoutes(ctx, routes); err != nil {
			return fmt.Errorf("failed to apply GraphQL routes after deletion: %w", err)
		}
	}

	h.invalidateCache()

	h.logger.Info("GraphQL route deleted",
		observability.String("key", key),
	)

	return nil
}

// handleGraphQLBackendUpdate handles GraphQL backend updates.
func (h *ConfigHandler) handleGraphQLBackendUpdate(
	ctx context.Context, resource *operatorv1alpha1.ConfigurationResource, key string,
) error {
	var backend config.GraphQLBackend
	if err := json.Unmarshal(resource.SpecJson, &backend); err != nil {
		return fmt.Errorf("failed to unmarshal GraphQL backend spec: %w", err)
	}

	h.mu.Lock()
	h.graphqlBackends[key] = &backend
	backends := h.collectGraphQLBackends()
	h.mu.Unlock()

	if h.applier != nil {
		if err := h.applier.ApplyGraphQLBackends(ctx, backends); err != nil {
			return fmt.Errorf("failed to apply GraphQL backends: %w", err)
		}
	}

	h.invalidateCache()

	h.logger.Info("GraphQL backend updated",
		observability.String("name", backend.Name),
		observability.String("key", key),
	)

	return nil
}

// handleGraphQLBackendDelete handles GraphQL backend deletion.
func (h *ConfigHandler) handleGraphQLBackendDelete(ctx context.Context, key string) error {
	h.mu.Lock()
	delete(h.graphqlBackends, key)
	backends := h.collectGraphQLBackends()
	h.mu.Unlock()

	if h.applier != nil {
		if err := h.applier.ApplyGraphQLBackends(ctx, backends); err != nil {
			return fmt.Errorf("failed to apply GraphQL backends after deletion: %w", err)
		}
	}

	h.invalidateCache()

	h.logger.Info("GraphQL backend deleted",
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

	// Defensive safeguard: never wipe a non-empty running configuration in
	// favor of an EMPTY snapshot. An empty FULL_SYNC is almost always the
	// result of an operator restart whose store has not been re-seeded by the
	// controllers yet (the proto carries no "intentionally empty" flag to
	// distinguish the two cases). Keep serving the last-known-good
	// configuration; the operator pushes a fresh FULL_SYNC as soon as its
	// store is populated, which is applied normally. Trade-off: deleting the
	// very last resource in the cluster is also skipped until the next
	// non-empty snapshot or a gateway restart — a deliberate
	// availability-over-consistency choice for the data plane.
	if snapshotIsEmpty(snapshot) && h.hasRunningConfig() {
		h.logger.Warn("received empty configuration snapshot while running configuration is non-empty; "+
			"keeping last-known-good configuration",
			observability.String("version", snapshot.Version),
			observability.String("checksum", snapshot.Checksum),
		)
		span.AddEvent("empty snapshot skipped: last-known-good configuration retained")
		return nil
	}

	// Post-reconnect regression guard: right after an operator restart the
	// operator's store may still be mid-seed, and its FULL_SYNC snapshots
	// carry PARTIAL (shrinking) resource sets. Defer applying any snapshot
	// whose resource count regresses versus the running configuration while
	// inside the stabilization window; the operator pushes a complete
	// snapshot as soon as its store finishes seeding, which grows the count
	// again and is applied normally. Trade-off (mirroring the empty-snapshot
	// guard above): a GENUINE shrink pushed within the window is deferred
	// until the next FULL_SYNC after the window — availability over
	// consistency for the data plane.
	if newCount, runningCount, deferred := h.shouldDeferRegressingSnapshot(snapshot); deferred {
		h.logger.Warn("received regressing configuration snapshot within post-reconnect window; "+
			"keeping last-known-good configuration",
			observability.String("version", snapshot.Version),
			observability.String("checksum", snapshot.Checksum),
			observability.Int("snapshot_resources", newCount),
			observability.Int("running_resources", runningCount),
		)
		span.AddEvent("regressing snapshot deferred: last-known-good configuration retained")
		return nil
	}

	// Decode every resource type before touching state so an undecodable
	// snapshot never leaves the handler half-cleared.
	routes, routeKeys := decodeResources[config.Route](h.logger, "route", snapshot.ApiRoutes)
	backends, backendKeys := decodeResources[config.Backend](h.logger, "backend", snapshot.Backends)
	grpcRoutes, grpcRouteKeys := decodeResources[config.GRPCRoute](h.logger, "gRPC route", snapshot.GrpcRoutes)
	grpcBackends, grpcBackendKeys := decodeResources[config.GRPCBackend](
		h.logger, "gRPC backend", snapshot.GrpcBackends)
	graphqlRoutes, graphqlRouteKeys := decodeResources[config.GraphQLRoute](
		h.logger, "GraphQL route", snapshot.GraphqlRoutes)
	graphqlBackends, graphqlBackendKeys := decodeResources[config.GraphQLBackend](
		h.logger, "GraphQL backend", snapshot.GraphqlBackends)

	// Replace the tracked state in a single atomic swap under one lock so
	// concurrent readers never observe a half-cleared configuration. State
	// is keyed by the SAME composite namespace/name key incremental updates
	// use (see HandleUpdate): a FULL_SYNC followed by an incremental
	// MODIFY/DELETE for the same resource must address the same map entry.
	h.mu.Lock()
	h.routes = stateMap(routes, routeKeys)
	h.backends = stateMap(backends, backendKeys)
	h.grpcRoutes = stateMap(grpcRoutes, grpcRouteKeys)
	h.grpcBackends = stateMap(grpcBackends, grpcBackendKeys)
	h.graphqlRoutes = stateMap(graphqlRoutes, graphqlRouteKeys)
	h.graphqlBackends = stateMap(graphqlBackends, graphqlBackendKeys)
	h.mu.Unlock()

	// Apply full configuration if applier supports it
	if h.applier != nil {
		cfg := &config.GatewayConfig{
			Spec: config.GatewaySpec{
				Routes:          routes,
				Backends:        backends,
				GRPCRoutes:      grpcRoutes,
				GRPCBackends:    grpcBackends,
				GraphQLRoutes:   graphqlRoutes,
				GraphQLBackends: graphqlBackends,
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
		observability.Int("graphql_routes", len(graphqlRoutes)),
		observability.Int("graphql_backends", len(graphqlBackends)),
	)

	return nil
}

// decodeResources decodes each resource's SpecJson into T. Successfully
// decoded items are returned in input order together with their composite
// state keys (resourceKey(namespace, name)), the SAME key shape incremental
// updates use in HandleUpdate, so snapshot-seeded and incrementally updated
// state address identical map entries. Undecodable resources are logged with
// the given kind label and skipped.
func decodeResources[T any](
	logger observability.Logger,
	kind string,
	resources []*operatorv1alpha1.ConfigurationResource,
) (items []T, keys []string) {
	items = make([]T, 0, len(resources))
	keys = make([]string, 0, len(resources))
	for _, r := range resources {
		var item T
		if err := json.Unmarshal(r.SpecJson, &item); err != nil {
			logger.Error("failed to parse "+kind,
				observability.String("name", r.Name),
				observability.Error(err),
			)
			continue
		}
		items = append(items, item)
		keys = append(keys, resourceKey(r.Namespace, r.Name))
	}
	return items, keys
}

// stateMap builds a state map from decoded items and their composite keys
// (parallel slices produced by decodeResources). Items are copied so state
// entries stay isolated from the slices handed to the applier.
func stateMap[T any](items []T, keys []string) map[string]*T {
	m := make(map[string]*T, len(items))
	for i := range items {
		item := items[i]
		m[keys[i]] = &item
	}
	return m
}

// collectSorted flattens a resource state map into a slice ordered by the
// composite state key (namespace/name). Go map iteration order is
// randomized, and the collected slices are pushed into routers/registries
// and logged — keys are unique, so key order keeps route loading, apply
// logs, and config diffs deterministic across processes and restarts.
func collectSorted[T any](m map[string]*T) []T {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	items := make([]T, 0, len(m))
	for _, k := range keys {
		items = append(items, *m[k])
	}
	return items
}

// collectRoutes collects all routes from the state in deterministic order.
func (h *ConfigHandler) collectRoutes() []config.Route {
	return collectSorted(h.routes)
}

// collectBackends collects all backends from the state in deterministic order.
func (h *ConfigHandler) collectBackends() []config.Backend {
	return collectSorted(h.backends)
}

// collectGRPCRoutes collects all gRPC routes from the state in deterministic order.
func (h *ConfigHandler) collectGRPCRoutes() []config.GRPCRoute {
	return collectSorted(h.grpcRoutes)
}

// collectGRPCBackends collects all gRPC backends from the state in deterministic order.
func (h *ConfigHandler) collectGRPCBackends() []config.GRPCBackend {
	return collectSorted(h.grpcBackends)
}

// collectGraphQLRoutes collects all GraphQL routes from the state, ordered by
// the SAME exported specificity function the GraphQL data-plane router uses
// in LoadRoutes (graphqlrouter.SortRoutesBySpecificity), so operator-applied
// route order, apply logs, and the router's matching order never diverge.
func (h *ConfigHandler) collectGraphQLRoutes() []config.GraphQLRoute {
	routes := collectSorted(h.graphqlRoutes)
	graphqlrouter.SortRoutesBySpecificity(routes)
	return routes
}

// collectGraphQLBackends collects all GraphQL backends from the state in
// deterministic order.
func (h *ConfigHandler) collectGraphQLBackends() []config.GraphQLBackend {
	return collectSorted(h.graphqlBackends)
}

// snapshotIsEmpty reports whether the snapshot carries no resources of any
// type. Resource slices are checked directly instead of trusting the
// TotalResources counter so a miscounted snapshot cannot bypass the
// empty-snapshot safeguard.
func snapshotIsEmpty(snapshot *operatorv1alpha1.ConfigurationSnapshot) bool {
	return len(snapshot.ApiRoutes) == 0 &&
		len(snapshot.Backends) == 0 &&
		len(snapshot.GrpcRoutes) == 0 &&
		len(snapshot.GrpcBackends) == 0 &&
		len(snapshot.GraphqlRoutes) == 0 &&
		len(snapshot.GraphqlBackends) == 0
}

// hasRunningConfig reports whether the handler currently tracks any resources.
func (h *ConfigHandler) hasRunningConfig() bool {
	return h.runningResourceCount() > 0
}

// runningResourceCount returns the total number of resources currently
// tracked by the handler across all resource types. Incremental updates keep
// the maps current, so this is always the size of the running configuration.
func (h *ConfigHandler) runningResourceCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.routes) + len(h.backends) +
		len(h.grpcRoutes) + len(h.grpcBackends) +
		len(h.graphqlRoutes) + len(h.graphqlBackends)
}

// countSnapshotResources counts the resources carried by a snapshot across
// all resource types. Resource slices are counted directly instead of
// trusting the TotalResources field, mirroring snapshotIsEmpty.
func countSnapshotResources(snapshot *operatorv1alpha1.ConfigurationSnapshot) int {
	return len(snapshot.ApiRoutes) + len(snapshot.Backends) +
		len(snapshot.GrpcRoutes) + len(snapshot.GrpcBackends) +
		len(snapshot.GraphqlRoutes) + len(snapshot.GraphqlBackends)
}

// MarkReconnected records an operator (re)connect and arms the snapshot
// regression window (see snapshotRegressionWindow). It is wired to the
// operator client's reconnect listener so both the initial connect and every
// stream re-establishment restart the window.
func (h *ConfigHandler) MarkReconnected() {
	h.reconnectedAt.Store(time.Now().UnixNano())
	h.logger.Debug("operator (re)connect recorded; snapshot regression window armed",
		observability.Duration("window", snapshotRegressionWindow),
	)
}

// withinReconnectWindow reports whether the handler is inside the
// post-(re)connect stabilization window. A zero timestamp (no reconnect ever
// signaled, e.g. embedded use without the listener wiring) keeps the window
// permanently inactive so snapshots always apply.
func (h *ConfigHandler) withinReconnectWindow() bool {
	markedAt := h.reconnectedAt.Load()
	if markedAt == 0 {
		return false
	}
	return time.Since(time.Unix(0, markedAt)) <= snapshotRegressionWindow
}

// shouldDeferRegressingSnapshot reports whether a FULL_SYNC snapshot must be
// deferred because its resource count regresses versus the running
// configuration while inside the post-reconnect stabilization window. The
// returned counts are exposed for logging.
func (h *ConfigHandler) shouldDeferRegressingSnapshot(
	snapshot *operatorv1alpha1.ConfigurationSnapshot,
) (newCount, runningCount int, deferred bool) {
	newCount = countSnapshotResources(snapshot)
	runningCount = h.runningResourceCount()
	deferred = newCount < runningCount && h.withinReconnectWindow()
	return newCount, runningCount, deferred
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
//
//nolint:gocritic // tooManyResultsChecker: extending existing 4-return pattern with GraphQL; struct refactor deferred
func (h *ConfigHandler) GetCurrentState() (
	routes []config.Route,
	backends []config.Backend,
	grpcRoutes []config.GRPCRoute,
	grpcBackends []config.GRPCBackend,
	graphqlRoutes []config.GraphQLRoute,
	graphqlBackends []config.GraphQLBackend,
) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return h.collectRoutes(), h.collectBackends(),
		h.collectGRPCRoutes(), h.collectGRPCBackends(),
		h.collectGraphQLRoutes(), h.collectGraphQLBackends()
}
