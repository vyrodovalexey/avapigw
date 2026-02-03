// Package webhook provides admission webhooks for the operator.
package webhook

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/operator/keys"
)

// DuplicateCheckerOption is a functional option for configuring DuplicateChecker.
type DuplicateCheckerOption func(*DuplicateChecker)

// WithNamespaceScoped configures the DuplicateChecker to only check for duplicates
// within the same namespace. This improves performance by reducing the scope of
// the duplicate check and is the recommended setting for most deployments.
func WithNamespaceScoped(namespaceScoped bool) DuplicateCheckerOption {
	return func(dc *DuplicateChecker) {
		dc.namespaceScoped = namespaceScoped
	}
}

// WithCacheEnabled enables caching of existing resources for efficient lookup.
func WithCacheEnabled(enabled bool) DuplicateCheckerOption {
	return func(dc *DuplicateChecker) {
		dc.cacheEnabled = enabled
	}
}

// WithCacheTTL sets the cache TTL duration.
func WithCacheTTL(ttl time.Duration) DuplicateCheckerOption {
	return func(dc *DuplicateChecker) {
		dc.cacheTTL = ttl
	}
}

// WithCleanupInterval sets the interval for automatic cache cleanup.
// The cleanup goroutine removes entries older than 2x TTL.
func WithCleanupInterval(interval time.Duration) DuplicateCheckerOption {
	return func(dc *DuplicateChecker) {
		dc.cleanupInterval = interval
	}
}

// DuplicateDetectionScope defines the scope for duplicate detection.
type DuplicateDetectionScope string

const (
	// ScopeNamespace checks for duplicates within the same namespace only.
	ScopeNamespace DuplicateDetectionScope = "namespace"

	// ScopeCluster checks for duplicates across all namespaces.
	ScopeCluster DuplicateDetectionScope = "cluster"
)

// Default cache configuration.
const (
	// defaultCacheTTL is the default time-to-live for cached entries.
	defaultCacheTTL = 30 * time.Second

	// defaultCleanupInterval is the default interval for cache cleanup.
	defaultCleanupInterval = 1 * time.Minute

	// cacheExpirationMultiplier determines when entries are considered stale (TTL * multiplier).
	cacheExpirationMultiplier = 2
)

// resourceCache holds cached resources for efficient duplicate detection.
type resourceCache struct {
	mu           sync.RWMutex
	apiRoutes    map[string]*avapigwv1alpha1.APIRouteList
	grpcRoutes   map[string]*avapigwv1alpha1.GRPCRouteList
	backends     map[string]*avapigwv1alpha1.BackendList
	grpcBackends map[string]*avapigwv1alpha1.GRPCBackendList
	lastRefresh  map[string]time.Time
}

// newResourceCache creates a new resource cache.
func newResourceCache() *resourceCache {
	return &resourceCache{
		apiRoutes:    make(map[string]*avapigwv1alpha1.APIRouteList),
		grpcRoutes:   make(map[string]*avapigwv1alpha1.GRPCRouteList),
		backends:     make(map[string]*avapigwv1alpha1.BackendList),
		grpcBackends: make(map[string]*avapigwv1alpha1.GRPCBackendList),
		lastRefresh:  make(map[string]time.Time),
	}
}

// DuplicateChecker checks for duplicate resources across the cluster or within a namespace.
type DuplicateChecker struct {
	client          client.Client
	logger          observability.Logger
	namespaceScoped bool // If true, only check for duplicates within the same namespace
	cacheEnabled    bool
	cacheTTL        time.Duration
	cleanupInterval time.Duration
	cache           *resourceCache

	// Cleanup goroutine lifecycle
	stopCleanup chan struct{}
	cleanupDone chan struct{}
}

// NewDuplicateChecker creates a new DuplicateChecker.
// By default, it checks for duplicates within the same namespace only (namespace-scoped).
// Use WithNamespaceScoped(false) to check across all namespaces.
// When caching is enabled, a background cleanup goroutine is started automatically.
// Call Stop() to gracefully shutdown the cleanup goroutine.
func NewDuplicateChecker(c client.Client, opts ...DuplicateCheckerOption) *DuplicateChecker {
	dc := &DuplicateChecker{
		client:          c,
		namespaceScoped: true, // Default to namespace-scoped for better performance
		cacheEnabled:    false,
		cacheTTL:        defaultCacheTTL,
		cleanupInterval: defaultCleanupInterval,
		cache:           newResourceCache(),
		stopCleanup:     make(chan struct{}),
		cleanupDone:     make(chan struct{}),
		logger: observability.GetGlobalLogger().With(
			observability.String("component", "duplicate-checker"),
		),
	}

	for _, opt := range opts {
		opt(dc)
	}

	// Start background cleanup goroutine if caching is enabled
	if dc.cacheEnabled {
		go dc.runCleanupLoop()
	}

	return dc
}

// GetScope returns the current duplicate detection scope.
func (c *DuplicateChecker) GetScope() DuplicateDetectionScope {
	if c.namespaceScoped {
		return ScopeNamespace
	}
	return ScopeCluster
}

// SetScope sets the duplicate detection scope.
func (c *DuplicateChecker) SetScope(scope DuplicateDetectionScope) {
	c.namespaceScoped = scope == ScopeNamespace
}

// isCacheValid checks if the cache for a given key is still valid.
func (c *DuplicateChecker) isCacheValid(cacheKey string) bool {
	if !c.cacheEnabled {
		return false
	}

	c.cache.mu.RLock()
	defer c.cache.mu.RUnlock()

	lastRefresh, ok := c.cache.lastRefresh[cacheKey]
	if !ok {
		return false
	}

	return time.Since(lastRefresh) < c.cacheTTL
}

// updateCacheTimestamp updates the cache timestamp for a given key.
func (c *DuplicateChecker) updateCacheTimestamp(cacheKey string) {
	c.cache.mu.Lock()
	defer c.cache.mu.Unlock()
	c.cache.lastRefresh[cacheKey] = time.Now()
}

// InvalidateCache invalidates all cached data.
func (c *DuplicateChecker) InvalidateCache() {
	c.cache.mu.Lock()
	defer c.cache.mu.Unlock()

	c.cache.apiRoutes = make(map[string]*avapigwv1alpha1.APIRouteList)
	c.cache.grpcRoutes = make(map[string]*avapigwv1alpha1.GRPCRouteList)
	c.cache.backends = make(map[string]*avapigwv1alpha1.BackendList)
	c.cache.grpcBackends = make(map[string]*avapigwv1alpha1.GRPCBackendList)
	c.cache.lastRefresh = make(map[string]time.Time)
}

// Stop gracefully shuts down the cache cleanup goroutine.
// This should be called when the DuplicateChecker is no longer needed.
func (c *DuplicateChecker) Stop() {
	if !c.cacheEnabled {
		return
	}

	close(c.stopCleanup)
	<-c.cleanupDone

	c.logger.Info("duplicate checker cache cleanup stopped")
}

// runCleanupLoop runs the background cache cleanup loop.
// It periodically removes cache entries older than 2x TTL.
func (c *DuplicateChecker) runCleanupLoop() {
	defer close(c.cleanupDone)

	ticker := time.NewTicker(c.cleanupInterval)
	defer ticker.Stop()

	c.logger.Info("starting cache cleanup loop",
		observability.Duration("interval", c.cleanupInterval),
		observability.Duration("ttl", c.cacheTTL),
	)

	for {
		select {
		case <-c.stopCleanup:
			c.logger.Debug("cache cleanup loop stopping")
			return
		case <-ticker.C:
			c.cleanupExpiredEntries()
		}
	}
}

// cleanupExpiredEntries removes cache entries older than 2x TTL.
func (c *DuplicateChecker) cleanupExpiredEntries() {
	c.cache.mu.Lock()
	defer c.cache.mu.Unlock()

	expirationThreshold := c.cacheTTL * cacheExpirationMultiplier
	now := time.Now()
	cleanedCount := 0

	for key, lastRefresh := range c.cache.lastRefresh {
		if now.Sub(lastRefresh) <= expirationThreshold {
			continue
		}
		// Remove from all cache maps
		delete(c.cache.apiRoutes, key)
		delete(c.cache.grpcRoutes, key)
		delete(c.cache.backends, key)
		delete(c.cache.grpcBackends, key)
		delete(c.cache.lastRefresh, key)
		cleanedCount++
	}

	if cleanedCount > 0 {
		c.logger.Debug("cleaned expired cache entries",
			observability.Int("count", cleanedCount),
		)
	}
}

// CheckAPIRouteDuplicate checks if an APIRoute with the same route match exists.
// If namespaceScoped is true, only checks within the same namespace for better performance.
func (c *DuplicateChecker) CheckAPIRouteDuplicate(
	ctx context.Context,
	route *avapigwv1alpha1.APIRoute,
) error {
	if c.client == nil {
		return nil
	}

	cacheKey := c.buildCacheKey("apiroute", route.Namespace)
	var routes *avapigwv1alpha1.APIRouteList

	// Try to use cached data
	if c.isCacheValid(cacheKey) {
		c.cache.mu.RLock()
		routes = c.cache.apiRoutes[cacheKey]
		c.cache.mu.RUnlock()
	}

	// Fetch from API if cache miss or invalid
	if routes == nil {
		routes = &avapigwv1alpha1.APIRouteList{}
		listOpts := []client.ListOption{}
		if c.namespaceScoped {
			listOpts = append(listOpts, client.InNamespace(route.Namespace))
		}
		if err := c.client.List(ctx, routes, listOpts...); err != nil {
			return fmt.Errorf("failed to list APIRoutes: %w", err)
		}

		// Update cache
		if c.cacheEnabled {
			c.cache.mu.Lock()
			c.cache.apiRoutes[cacheKey] = routes
			c.cache.mu.Unlock()
			c.updateCacheTimestamp(cacheKey)
		}
	}

	// Check for duplicates based on route match criteria
	var conflicts []string
	for i := range routes.Items {
		existing := &routes.Items[i]
		// Skip self
		if existing.Namespace == route.Namespace && existing.Name == route.Name {
			continue
		}

		// Check for overlapping routes
		if c.routesOverlap(route, existing) {
			conflicts = append(conflicts, keys.ResourceKey(existing.Namespace, existing.Name))
		}
	}

	if len(conflicts) > 0 {
		c.logger.Warn("duplicate APIRoute detected",
			observability.String("new_route", keys.ResourceKey(route.Namespace, route.Name)),
			observability.Any("conflicting_routes", conflicts),
		)
		return fmt.Errorf(
			"APIRoute %s/%s conflicts with existing route(s) %s: overlapping path/method combination",
			route.Namespace, route.Name, strings.Join(conflicts, ", "))
	}

	return nil
}

// buildCacheKey builds a cache key for the given resource type and namespace.
func (c *DuplicateChecker) buildCacheKey(resourceType, namespace string) string {
	if c.namespaceScoped {
		return fmt.Sprintf("%s/%s", resourceType, namespace)
	}
	return fmt.Sprintf("%s/cluster", resourceType)
}

// CheckBackendDuplicate checks if a Backend with the same host:port combination exists.
// If namespaceScoped is true, only checks within the same namespace for better performance.
func (c *DuplicateChecker) CheckBackendDuplicate(
	ctx context.Context,
	backend *avapigwv1alpha1.Backend,
) error {
	if c.client == nil {
		return nil
	}

	cacheKey := c.buildCacheKey("backend", backend.Namespace)
	var backends *avapigwv1alpha1.BackendList

	// Try to use cached data
	if c.isCacheValid(cacheKey) {
		c.cache.mu.RLock()
		backends = c.cache.backends[cacheKey]
		c.cache.mu.RUnlock()
	}

	// Fetch from API if cache miss or invalid
	if backends == nil {
		backends = &avapigwv1alpha1.BackendList{}
		listOpts := []client.ListOption{}
		if c.namespaceScoped {
			listOpts = append(listOpts, client.InNamespace(backend.Namespace))
		}
		if err := c.client.List(ctx, backends, listOpts...); err != nil {
			return fmt.Errorf("failed to list Backends: %w", err)
		}

		// Update cache
		if c.cacheEnabled {
			c.cache.mu.Lock()
			c.cache.backends[cacheKey] = backends
			c.cache.mu.Unlock()
			c.updateCacheTimestamp(cacheKey)
		}
	}

	// Check for duplicates based on host:port combination
	var conflicts []string
	for i := range backends.Items {
		existing := &backends.Items[i]
		// Skip self
		if existing.Namespace == backend.Namespace && existing.Name == backend.Name {
			continue
		}

		// Check for same host:port combination
		if c.backendsConflict(backend, existing) {
			conflicts = append(conflicts, keys.ResourceKey(existing.Namespace, existing.Name))
		}
	}

	if len(conflicts) > 0 {
		c.logger.Warn("duplicate Backend detected",
			observability.String("new_backend", keys.ResourceKey(backend.Namespace, backend.Name)),
			observability.Any("conflicting_backends", conflicts),
		)
		//nolint:staticcheck // Error message is intentionally capitalized for resource name consistency
		return fmt.Errorf(
			"backend %s/%s conflicts with existing backend(s) %s: same host:port combination",
			backend.Namespace, backend.Name, strings.Join(conflicts, ", "))
	}

	return nil
}

// CheckGRPCRouteDuplicate checks if a GRPCRoute with the same service/method match exists.
// If namespaceScoped is true, only checks within the same namespace for better performance.
func (c *DuplicateChecker) CheckGRPCRouteDuplicate(
	ctx context.Context,
	route *avapigwv1alpha1.GRPCRoute,
) error {
	if c.client == nil {
		return nil
	}

	cacheKey := c.buildCacheKey("grpcroute", route.Namespace)
	var routes *avapigwv1alpha1.GRPCRouteList

	// Try to use cached data
	if c.isCacheValid(cacheKey) {
		c.cache.mu.RLock()
		routes = c.cache.grpcRoutes[cacheKey]
		c.cache.mu.RUnlock()
	}

	// Fetch from API if cache miss or invalid
	if routes == nil {
		routes = &avapigwv1alpha1.GRPCRouteList{}
		listOpts := []client.ListOption{}
		if c.namespaceScoped {
			listOpts = append(listOpts, client.InNamespace(route.Namespace))
		}
		if err := c.client.List(ctx, routes, listOpts...); err != nil {
			return fmt.Errorf("failed to list GRPCRoutes: %w", err)
		}

		// Update cache
		if c.cacheEnabled {
			c.cache.mu.Lock()
			c.cache.grpcRoutes[cacheKey] = routes
			c.cache.mu.Unlock()
			c.updateCacheTimestamp(cacheKey)
		}
	}

	// Check for duplicates based on service/method combination
	var conflicts []string
	for i := range routes.Items {
		existing := &routes.Items[i]
		if existing.Namespace == route.Namespace && existing.Name == route.Name {
			continue
		}

		if c.grpcRoutesOverlap(route, existing) {
			conflicts = append(conflicts, keys.ResourceKey(existing.Namespace, existing.Name))
		}
	}

	if len(conflicts) > 0 {
		c.logger.Warn("duplicate GRPCRoute detected",
			observability.String("new_route", keys.ResourceKey(route.Namespace, route.Name)),
			observability.Any("conflicting_routes", conflicts),
		)
		return fmt.Errorf(
			"GRPCRoute %s/%s conflicts with existing route(s) %s: overlapping service/method",
			route.Namespace, route.Name, strings.Join(conflicts, ", "))
	}

	return nil
}

// CheckGRPCBackendDuplicate checks if a GRPCBackend with the same host:port combination exists.
// If namespaceScoped is true, only checks within the same namespace for better performance.
func (c *DuplicateChecker) CheckGRPCBackendDuplicate(
	ctx context.Context,
	backend *avapigwv1alpha1.GRPCBackend,
) error {
	if c.client == nil {
		return nil
	}

	cacheKey := c.buildCacheKey("grpcbackend", backend.Namespace)
	var backends *avapigwv1alpha1.GRPCBackendList

	// Try to use cached data
	if c.isCacheValid(cacheKey) {
		c.cache.mu.RLock()
		backends = c.cache.grpcBackends[cacheKey]
		c.cache.mu.RUnlock()
	}

	// Fetch from API if cache miss or invalid
	if backends == nil {
		backends = &avapigwv1alpha1.GRPCBackendList{}
		listOpts := []client.ListOption{}
		if c.namespaceScoped {
			listOpts = append(listOpts, client.InNamespace(backend.Namespace))
		}
		if err := c.client.List(ctx, backends, listOpts...); err != nil {
			return fmt.Errorf("failed to list GRPCBackends: %w", err)
		}

		// Update cache
		if c.cacheEnabled {
			c.cache.mu.Lock()
			c.cache.grpcBackends[cacheKey] = backends
			c.cache.mu.Unlock()
			c.updateCacheTimestamp(cacheKey)
		}
	}

	// Check for duplicates based on host:port combination
	var conflicts []string
	for i := range backends.Items {
		existing := &backends.Items[i]
		if existing.Namespace == backend.Namespace && existing.Name == backend.Name {
			continue
		}

		if c.grpcBackendsConflict(backend, existing) {
			conflicts = append(conflicts, keys.ResourceKey(existing.Namespace, existing.Name))
		}
	}

	if len(conflicts) > 0 {
		c.logger.Warn("duplicate GRPCBackend detected",
			observability.String("new_backend", keys.ResourceKey(backend.Namespace, backend.Name)),
			observability.Any("conflicting_backends", conflicts),
		)
		return fmt.Errorf(
			"GRPCBackend %s/%s conflicts with existing backend(s) %s: same host:port",
			backend.Namespace, backend.Name, strings.Join(conflicts, ", "))
	}

	return nil
}

// routesOverlap checks if two APIRoutes have overlapping match conditions.
func (c *DuplicateChecker) routesOverlap(a, b *avapigwv1alpha1.APIRoute) bool {
	// If either route has no match conditions, they don't overlap
	// (empty match means catch-all, but we allow multiple catch-alls)
	if len(a.Spec.Match) == 0 || len(b.Spec.Match) == 0 {
		return false
	}

	// Check if any match conditions overlap
	for i := range a.Spec.Match {
		matchA := &a.Spec.Match[i]
		for j := range b.Spec.Match {
			matchB := &b.Spec.Match[j]
			if c.matchConditionsOverlap(matchA, matchB) {
				return true
			}
		}
	}
	return false
}

// matchConditionsOverlap checks if two RouteMatch conditions overlap.
//
//nolint:gocyclo // URI matching requires checking multiple conditions for exact, prefix, and regex patterns
func (c *DuplicateChecker) matchConditionsOverlap(a, b *avapigwv1alpha1.RouteMatch) bool {
	if a.URI == nil || b.URI == nil {
		return false
	}

	// Check exact match overlap
	if c.exactURIsOverlap(a, b) {
		return c.methodsOverlap(a.Methods, b.Methods)
	}

	// Check prefix overlap
	if c.prefixURIsOverlap(a, b) {
		return c.methodsOverlap(a.Methods, b.Methods)
	}

	// Check exact and prefix overlap
	if c.exactAndPrefixOverlap(a, b) {
		return c.methodsOverlap(a.Methods, b.Methods)
	}

	return false
}

// exactURIsOverlap checks if two exact URIs match.
func (c *DuplicateChecker) exactURIsOverlap(a, b *avapigwv1alpha1.RouteMatch) bool {
	return a.URI.Exact != "" && b.URI.Exact != "" && a.URI.Exact == b.URI.Exact
}

// prefixURIsOverlap checks if two prefix URIs overlap.
func (c *DuplicateChecker) prefixURIsOverlap(a, b *avapigwv1alpha1.RouteMatch) bool {
	if a.URI.Prefix == "" || b.URI.Prefix == "" {
		return false
	}
	return strings.HasPrefix(a.URI.Prefix, b.URI.Prefix) ||
		strings.HasPrefix(b.URI.Prefix, a.URI.Prefix)
}

// exactAndPrefixOverlap checks if an exact URI overlaps with a prefix URI.
func (c *DuplicateChecker) exactAndPrefixOverlap(a, b *avapigwv1alpha1.RouteMatch) bool {
	if a.URI.Exact != "" && b.URI.Prefix != "" && strings.HasPrefix(a.URI.Exact, b.URI.Prefix) {
		return true
	}
	if b.URI.Exact != "" && a.URI.Prefix != "" && strings.HasPrefix(b.URI.Exact, a.URI.Prefix) {
		return true
	}
	return false
}

// methodsOverlap checks if two method lists overlap.
func (c *DuplicateChecker) methodsOverlap(a, b []string) bool {
	// Empty means all methods
	if len(a) == 0 || len(b) == 0 {
		return true
	}
	for _, ma := range a {
		for _, mb := range b {
			if strings.EqualFold(ma, mb) {
				return true
			}
		}
	}
	return false
}

// backendsConflict checks if two Backends have the same host:port combination.
func (c *DuplicateChecker) backendsConflict(a, b *avapigwv1alpha1.Backend) bool {
	// Check if any hosts have the same address:port
	for _, hostA := range a.Spec.Hosts {
		for _, hostB := range b.Spec.Hosts {
			if hostA.Address == hostB.Address && hostA.Port == hostB.Port {
				return true
			}
		}
	}
	return false
}

// grpcRoutesOverlap checks if two GRPCRoutes have overlapping match conditions.
func (c *DuplicateChecker) grpcRoutesOverlap(a, b *avapigwv1alpha1.GRPCRoute) bool {
	// If either route has no match conditions, they don't overlap
	if len(a.Spec.Match) == 0 || len(b.Spec.Match) == 0 {
		return false
	}

	// Check if service/method combinations overlap
	for i := range a.Spec.Match {
		matchA := &a.Spec.Match[i]
		for j := range b.Spec.Match {
			matchB := &b.Spec.Match[j]
			if c.grpcMatchConditionsOverlap(matchA, matchB) {
				return true
			}
		}
	}
	return false
}

// grpcMatchConditionsOverlap checks if two GRPCRouteMatch conditions overlap.
//
//nolint:gocognit // gRPC matching requires checking multiple nested conditions for service and method patterns
func (c *DuplicateChecker) grpcMatchConditionsOverlap(
	a, b *avapigwv1alpha1.GRPCRouteMatch,
) bool {
	if a.Service == nil || b.Service == nil {
		return false
	}

	// Check exact service match
	if c.exactServicesMatch(a, b) {
		return c.grpcMethodsOverlap(a, b)
	}

	// Check prefix service overlap
	if c.prefixServicesOverlap(a, b) {
		return c.grpcMethodsOverlapForPrefix(a, b)
	}

	return false
}

// exactServicesMatch checks if two services have exact match.
func (c *DuplicateChecker) exactServicesMatch(
	a, b *avapigwv1alpha1.GRPCRouteMatch,
) bool {
	return a.Service.Exact != "" && b.Service.Exact != "" && a.Service.Exact == b.Service.Exact
}

// prefixServicesOverlap checks if two service prefixes overlap.
func (c *DuplicateChecker) prefixServicesOverlap(
	a, b *avapigwv1alpha1.GRPCRouteMatch,
) bool {
	if a.Service.Prefix == "" || b.Service.Prefix == "" {
		return false
	}
	return strings.HasPrefix(a.Service.Prefix, b.Service.Prefix) ||
		strings.HasPrefix(b.Service.Prefix, a.Service.Prefix)
}

// grpcMethodsOverlap checks if gRPC methods overlap for exact service match.
func (c *DuplicateChecker) grpcMethodsOverlap(
	a, b *avapigwv1alpha1.GRPCRouteMatch,
) bool {
	// If no method specified on either, all methods match
	if a.Method == nil || b.Method == nil {
		return true
	}

	// Check exact method match
	if a.Method.Exact != "" && b.Method.Exact != "" && a.Method.Exact == b.Method.Exact {
		return true
	}

	// Check prefix overlap for methods
	if a.Method.Prefix != "" && b.Method.Prefix != "" {
		return strings.HasPrefix(a.Method.Prefix, b.Method.Prefix) ||
			strings.HasPrefix(b.Method.Prefix, a.Method.Prefix)
	}

	return false
}

// grpcMethodsOverlapForPrefix checks if gRPC methods overlap for prefix service match.
func (c *DuplicateChecker) grpcMethodsOverlapForPrefix(
	a, b *avapigwv1alpha1.GRPCRouteMatch,
) bool {
	// If no method specified on either, all methods match
	if a.Method == nil || b.Method == nil {
		return true
	}

	// Check exact method match
	return a.Method.Exact != "" && b.Method.Exact != "" && a.Method.Exact == b.Method.Exact
}

// grpcBackendsConflict checks if two GRPCBackends have the same host:port combination.
func (c *DuplicateChecker) grpcBackendsConflict(a, b *avapigwv1alpha1.GRPCBackend) bool {
	// Check if any hosts have the same address:port
	for _, hostA := range a.Spec.Hosts {
		for _, hostB := range b.Spec.Hosts {
			if hostA.Address == hostB.Address && hostA.Port == hostB.Port {
				return true
			}
		}
	}
	return false
}
