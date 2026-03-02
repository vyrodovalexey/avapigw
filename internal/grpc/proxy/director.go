package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/vyrodovalexey/avapigw/internal/auth"
	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/grpc/router"
	backendmetrics "github.com/vyrodovalexey/avapigw/internal/metrics/backend"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// Director determines the backend destination for a gRPC request.
type Director interface {
	// Direct returns the backend connection and context for a request.
	Direct(ctx context.Context, fullMethod string) (context.Context, *grpc.ClientConn, error)
}

// RouterDirector uses the gRPC router to determine backend destinations.
type RouterDirector struct {
	router          *router.Router
	connPool        *ConnectionPool
	backendRegistry *backend.Registry
	logger          observability.Logger
	counter         atomic.Uint64 // for round-robin selection
	authMetrics     *auth.Metrics
	authCache       map[string]auth.GRPCAuthenticator
	authCacheMu     sync.RWMutex
	vaultClient     vault.Client
}

// DirectorOption is a functional option for configuring the director.
type DirectorOption func(*RouterDirector)

// WithDirectorLogger sets the logger for the director.
func WithDirectorLogger(logger observability.Logger) DirectorOption {
	return func(d *RouterDirector) {
		d.logger = logger
	}
}

// WithDirectorBackendRegistry sets the backend registry for the director.
// When set, the director resolves backend names to actual host addresses
// using the backend's load balancer instead of using the route destination
// host directly.
func WithDirectorBackendRegistry(registry *backend.Registry) DirectorOption {
	return func(d *RouterDirector) {
		d.backendRegistry = registry
	}
}

// WithDirectorAuthMetrics sets the authentication metrics for the director.
// When set, per-route authentication operations emit Prometheus metrics.
func WithDirectorAuthMetrics(metrics *auth.Metrics) DirectorOption {
	return func(d *RouterDirector) {
		d.authMetrics = metrics
	}
}

// WithDirectorVaultClient sets the vault client for the director.
// When set, per-route API key authentication can use Vault as the key store.
func WithDirectorVaultClient(client vault.Client) DirectorOption {
	return func(d *RouterDirector) {
		d.vaultClient = client
	}
}

// NewRouterDirector creates a new router-based director.
func NewRouterDirector(r *router.Router, pool *ConnectionPool, opts ...DirectorOption) *RouterDirector {
	d := &RouterDirector{
		router:    r,
		connPool:  pool,
		logger:    observability.NopLogger(),
		authCache: make(map[string]auth.GRPCAuthenticator),
	}

	for _, opt := range opts {
		opt(d)
	}

	return d
}

// Direct returns the backend connection and context for a request.
func (d *RouterDirector) Direct(ctx context.Context, fullMethod string) (context.Context, *grpc.ClientConn, error) {
	start := time.Now()
	metrics := getGRPCProxyMetrics()

	// Extract metadata from incoming context
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		md = metadata.MD{}
	}

	// Match route
	result, err := d.router.Match(fullMethod, md)
	if err != nil {
		d.logger.Debug("no matching route",
			observability.String("method", fullMethod),
			observability.Error(err),
		)
		metrics.directRequests.WithLabelValues(fullMethod, "no_route").Inc()
		metrics.directDuration.WithLabelValues(fullMethod).Observe(time.Since(start).Seconds())
		return ctx, nil, fmt.Errorf("no matching route for %s: %w", fullMethod, err)
	}

	// Apply per-route authentication if configured
	if result.Route.Config.Authentication != nil && result.Route.Config.Authentication.Enabled {
		if authErr := d.authenticateRoute(ctx, result.Route); authErr != nil {
			metrics.directRequests.WithLabelValues(fullMethod, "auth_failed").Inc()
			metrics.directDuration.WithLabelValues(fullMethod).Observe(time.Since(start).Seconds())
			return ctx, nil, authErr
		}
	}

	// Select destination
	dest := d.selectDestination(result.Route.Config.Route)
	if dest == nil {
		metrics.directRequests.WithLabelValues(fullMethod, "no_destination").Inc()
		metrics.directDuration.WithLabelValues(fullMethod).Observe(time.Since(start).Seconds())
		return ctx, nil, fmt.Errorf("no destination available for route %s", result.Route.Name)
	}

	// Resolve target address: use backend registry if available, otherwise use
	// the route destination host and port directly.
	target, backendHost, serviceBackend, resolveErr := d.resolveTarget(dest)
	if resolveErr != nil {
		d.logger.Warn("no available hosts for backend",
			observability.String("backend", dest.Destination.Host),
			observability.String("route", result.Route.Name),
			observability.Error(resolveErr),
		)
		metrics.directRequests.WithLabelValues(fullMethod, "no_hosts").Inc()
		metrics.directDuration.WithLabelValues(fullMethod).Observe(time.Since(start).Seconds())
		return ctx, nil, fmt.Errorf("no available hosts for backend %s: %w", dest.Destination.Host, resolveErr)
	}
	// Release the host connection count after the request completes
	if serviceBackend != nil && backendHost != nil {
		defer serviceBackend.ReleaseHost(backendHost)
	}

	// Record backend selection decision
	selectionStrategy := "weighted"
	if len(result.Route.Config.Route) == 1 {
		selectionStrategy = "single"
	}
	metrics.backendSelections.WithLabelValues(
		result.Route.Name, target, selectionStrategy,
	).Inc()

	// Record backend-level LB selection (new backend metrics package)
	backendmetrics.GetBackendMetrics().RecordLBSelection(
		dest.Destination.Host, selectionStrategy,
	)

	// Get connection from pool — use per-backend TLS if available (Feature 3)
	var backendTLS *tls.Config
	if serviceBackend != nil {
		backendTLS = serviceBackend.TLSConfig()
	}
	conn, err := d.connPool.GetWithTLS(ctx, target, backendTLS)
	if err != nil {
		d.logger.Error("failed to get connection",
			observability.String("target", target),
			observability.Error(err),
		)
		metrics.directRequests.WithLabelValues(fullMethod, "connection_error").Inc()
		metrics.directDuration.WithLabelValues(fullMethod).Observe(time.Since(start).Seconds())
		// Record backend-level connection error (new backend metrics package)
		backendmetrics.GetBackendMetrics().RecordConnectionError(
			dest.Destination.Host, "connection_refused",
		)
		return ctx, nil, fmt.Errorf("failed to connect to %s: %w", target, err)
	}

	// Create outgoing context with metadata and apply request transforms
	outCtx := d.createOutgoingContext(ctx, md, result.Route.Name, &result.Route.Config)

	// Inject backend auth token if the backend has an auth provider (Feature 4)
	if serviceBackend != nil {
		var authErr error
		outCtx, authErr = d.injectBackendAuth(outCtx, serviceBackend, result.Route.Name)
		if authErr != nil {
			d.logger.Error("failed to inject backend auth",
				observability.String("route", result.Route.Name),
				observability.String("target", target),
				observability.Error(authErr),
			)
			metrics.directRequests.WithLabelValues(fullMethod, "backend_auth_error").Inc()
			metrics.directDuration.WithLabelValues(fullMethod).Observe(time.Since(start).Seconds())
			return ctx, nil, status.Errorf(codes.Internal, "backend auth injection failed: %v", authErr)
		}
	}

	metrics.directRequests.WithLabelValues(fullMethod, "success").Inc()
	metrics.directDuration.WithLabelValues(fullMethod).Observe(time.Since(start).Seconds())

	d.logger.Debug("directing request",
		observability.String("method", fullMethod),
		observability.String("route", result.Route.Name),
		observability.String("target", target),
	)

	return outCtx, conn, nil
}

// authenticateRoute performs per-route authentication for a matched gRPC route.
// It retrieves or creates a cached authenticator for the route and invokes it.
// Returns a gRPC status error on failure so the caller can propagate it directly.
func (d *RouterDirector) authenticateRoute(ctx context.Context, route *router.CompiledGRPCRoute) error {
	authenticator, err := d.getOrCreateAuthenticator(route.Name, route.Config.Authentication)
	if err != nil {
		d.logger.Error("failed to create gRPC authenticator",
			observability.String("route", route.Name),
			observability.Error(err),
		)
		return status.Error(codes.Internal, "authentication configuration error")
	}

	identity, err := authenticator.Authenticate(ctx)
	if err != nil {
		d.logger.Warn("gRPC per-route authentication failed",
			observability.String("route", route.Name),
			observability.Error(err),
		)
		if errors.Is(err, auth.ErrNoCredentials) {
			return status.Error(codes.Unauthenticated, "authentication required")
		}
		return status.Error(codes.Unauthenticated, "authentication failed")
	}

	// Identity is stored in context by the authenticator; log for audit trail.
	_ = identity
	return nil
}

// getOrCreateAuthenticator returns a cached GRPCAuthenticator for the given
// route name, creating one from the supplied config on first access.
// The cache avoids re-parsing configuration and re-initializing validators
// on every request.
func (d *RouterDirector) getOrCreateAuthenticator(
	routeName string, authCfg *config.AuthenticationConfig,
) (auth.GRPCAuthenticator, error) {
	// Fast path: check cache under read lock.
	d.authCacheMu.RLock()
	if cached, ok := d.authCache[routeName]; ok {
		d.authCacheMu.RUnlock()
		return cached, nil
	}
	d.authCacheMu.RUnlock()

	// Slow path: create authenticator under write lock with double-check.
	d.authCacheMu.Lock()
	defer d.authCacheMu.Unlock()

	// Double-check after acquiring write lock.
	if cached, ok := d.authCache[routeName]; ok {
		return cached, nil
	}

	authConfig, err := auth.ConvertFromGatewayConfig(authCfg)
	if err != nil {
		return nil, fmt.Errorf("convert auth config for route %s: %w", routeName, err)
	}
	if authConfig == nil {
		return nil, fmt.Errorf("auth config conversion returned nil for route %s", routeName)
	}

	opts := []auth.GRPCAuthenticatorOption{
		auth.WithGRPCAuthenticatorLogger(d.logger),
	}
	if d.authMetrics != nil {
		opts = append(opts, auth.WithGRPCAuthenticatorMetrics(d.authMetrics))
	}
	if d.vaultClient != nil {
		opts = append(opts, auth.WithGRPCVaultClient(d.vaultClient))
	}

	authenticator, err := auth.NewGRPCAuthenticator(authConfig, opts...)
	if err != nil {
		return nil, fmt.Errorf("create gRPC authenticator for route %s: %w", routeName, err)
	}

	d.authCache[routeName] = authenticator

	d.logger.Debug("created gRPC route authenticator",
		observability.String("route", routeName),
	)

	return authenticator, nil
}

// resolveTarget resolves the target address for a destination.
// When a backend registry is available and the destination host matches a registered
// backend, the backend's load balancer is used to select an actual host. Otherwise,
// the destination host and port are used directly.
func (d *RouterDirector) resolveTarget(
	dest *config.RouteDestination,
) (target string, host *backend.Host, sb *backend.ServiceBackend, err error) {
	sb = d.getServiceBackend(dest.Destination.Host)
	if sb == nil {
		// No backend found — use destination host:port directly (backward compatible)
		return fmt.Sprintf("%s:%d", dest.Destination.Host, dest.Destination.Port), nil, nil, nil
	}

	host, err = sb.GetAvailableHost()
	if err != nil {
		return "", nil, nil, err
	}

	target = host.Address + ":" + strconv.Itoa(host.Port)
	return target, host, sb, nil
}

// getServiceBackend retrieves the service backend from the registry.
func (d *RouterDirector) getServiceBackend(host string) *backend.ServiceBackend {
	if d.backendRegistry == nil {
		return nil
	}
	b, ok := d.backendRegistry.Get(host)
	if !ok {
		return nil
	}
	sb, _ := b.(*backend.ServiceBackend)
	return sb
}

// selectDestination selects a destination based on weights.
func (d *RouterDirector) selectDestination(destinations []config.RouteDestination) *config.RouteDestination {
	if len(destinations) == 0 {
		return nil
	}

	if len(destinations) == 1 {
		return &destinations[0]
	}

	// Calculate total weight
	totalWeight := 0
	for _, dest := range destinations {
		weight := dest.Weight
		if weight == 0 {
			weight = 1
		}
		totalWeight += weight
	}

	// If all weights are 0 or equal, use round-robin
	if totalWeight == 0 || totalWeight == len(destinations) {
		idx := d.counter.Add(1) % uint64(len(destinations))
		return &destinations[idx]
	}

	// Weighted random selection
	r := rand.Intn(totalWeight) //nolint:gosec // not security-sensitive
	cumulative := 0
	for i := range destinations {
		weight := destinations[i].Weight
		if weight == 0 {
			weight = 1
		}
		cumulative += weight
		if r < cumulative {
			return &destinations[i]
		}
	}

	return &destinations[0]
}

// createOutgoingContext creates the outgoing context with forwarded metadata.
// When routeCfg is provided, request metadata transforms are applied.
func (d *RouterDirector) createOutgoingContext(
	ctx context.Context, inMD metadata.MD, routeName string, routeCfg *config.GRPCRoute,
) context.Context {
	// Copy incoming metadata to outgoing
	outMD := metadata.MD{}
	for k, v := range inMD {
		// Skip pseudo-headers and hop-by-hop headers
		if shouldForwardMetadata(k) {
			outMD[k] = v
		}
	}

	// Add gateway-specific headers
	outMD.Set("x-gateway-route", routeName)

	// Apply request metadata transforms from route config (Feature 2)
	if routeCfg != nil && routeCfg.Transform != nil && routeCfg.Transform.Request != nil {
		outMD = d.applyRequestMetadataTransforms(outMD, routeCfg.Transform.Request, routeName)

		// Apply authority override
		if routeCfg.Transform.Request.AuthorityOverride != "" {
			outMD.Set(":authority", routeCfg.Transform.Request.AuthorityOverride)
			d.logger.Debug("applied authority override",
				observability.String("route", routeName),
				observability.String("authority", routeCfg.Transform.Request.AuthorityOverride),
			)
		}
	}

	return metadata.NewOutgoingContext(ctx, outMD)
}

// applyRequestMetadataTransforms applies request metadata transforms from the route config.
// It adds static metadata and removes specified metadata keys.
func (d *RouterDirector) applyRequestMetadataTransforms(
	outMD metadata.MD, reqCfg *config.GRPCRequestTransformConfig, routeName string,
) metadata.MD {
	metrics := getGRPCProxyMetrics()
	transformCount := 0

	// Add static metadata
	if len(reqCfg.StaticMetadata) > 0 {
		for k, v := range reqCfg.StaticMetadata {
			outMD.Set(k, v)
		}
		transformCount += len(reqCfg.StaticMetadata)
		d.logger.Debug("applied static metadata transforms",
			observability.String("route", routeName),
			observability.Int("count", len(reqCfg.StaticMetadata)),
		)
	}

	// Remove specified metadata keys
	if len(reqCfg.RemoveFields) > 0 {
		for _, key := range reqCfg.RemoveFields {
			delete(outMD, key)
		}
		transformCount += len(reqCfg.RemoveFields)
		d.logger.Debug("removed metadata keys",
			observability.String("route", routeName),
			observability.Int("count", len(reqCfg.RemoveFields)),
		)
	}

	if transformCount > 0 {
		metrics.transformOperations.WithLabelValues(
			routeName, "request", "metadata",
		).Inc()
	}

	return outMD
}

// injectBackendAuth injects backend authentication tokens into the outgoing context.
// It uses the backend's auth provider to get credentials and merges them into
// the outgoing gRPC metadata. This reuses the existing ApplyHTTP mechanism
// which handles token caching, refresh, etc.
func (d *RouterDirector) injectBackendAuth(
	ctx context.Context, sb *backend.ServiceBackend, routeName string,
) (context.Context, error) {
	provider := sb.AuthProvider()
	if provider == nil || provider.Type() == "none" {
		return ctx, nil
	}

	metrics := getGRPCProxyMetrics()

	// Use ApplyHTTP to get the auth header, then inject as gRPC metadata.
	// This reuses the existing token caching and refresh logic.
	fakeReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://backend-auth", nil)
	if err != nil {
		metrics.backendAuthFailure.WithLabelValues(routeName, provider.Type()).Inc()
		return ctx, fmt.Errorf("failed to create auth request: %w", err)
	}

	if applyErr := provider.ApplyHTTP(ctx, fakeReq); applyErr != nil {
		metrics.backendAuthFailure.WithLabelValues(routeName, provider.Type()).Inc()
		return ctx, fmt.Errorf("backend auth failed: %w", applyErr)
	}

	// Extract auth header and inject as gRPC metadata
	authHeader := fakeReq.Header.Get("Authorization")
	if authHeader == "" {
		// No auth header produced — provider may be a no-op type
		return ctx, nil
	}

	md, _ := metadata.FromOutgoingContext(ctx)
	md = md.Copy()
	md.Set("authorization", authHeader)

	metrics.backendAuthSuccess.WithLabelValues(routeName, provider.Type()).Inc()

	d.logger.Debug("injected backend auth token",
		observability.String("route", routeName),
		observability.String("auth_type", provider.Type()),
	)

	return metadata.NewOutgoingContext(ctx, md), nil
}

// shouldForwardMetadata returns true if the metadata key should be forwarded.
func shouldForwardMetadata(key string) bool {
	// Skip pseudo-headers (start with :)
	if key != "" && key[0] == ':' {
		return false
	}

	// Skip hop-by-hop headers
	hopByHopHeaders := map[string]bool{
		"connection":          true,
		"keep-alive":          true,
		"proxy-authenticate":  true,
		"proxy-authorization": true,
		"te":                  true,
		"trailer":             true,
		"transfer-encoding":   true,
		"upgrade":             true,
	}

	return !hopByHopHeaders[key]
}

// ClearAuthCache clears the cached gRPC authenticators.
// This should be called when route authentication configuration changes
// (e.g., CRD updates) so that the next request rebuilds the authenticator
// from the updated config.
func (d *RouterDirector) ClearAuthCache() {
	d.authCacheMu.Lock()
	defer d.authCacheMu.Unlock()
	d.authCache = make(map[string]auth.GRPCAuthenticator)
	d.logger.Debug("gRPC auth cache cleared")
}

// StaticDirector always directs to a fixed target.
type StaticDirector struct {
	target   string
	connPool *ConnectionPool
	logger   observability.Logger
}

// NewStaticDirector creates a new static director.
func NewStaticDirector(target string, pool *ConnectionPool, logger observability.Logger) *StaticDirector {
	return &StaticDirector{
		target:   target,
		connPool: pool,
		logger:   logger,
	}
}

// Direct returns the backend connection for the static target.
func (d *StaticDirector) Direct(ctx context.Context, fullMethod string) (context.Context, *grpc.ClientConn, error) {
	conn, err := d.connPool.Get(ctx, d.target)
	if err != nil {
		return ctx, nil, fmt.Errorf("failed to connect to %s: %w", d.target, err)
	}

	// Extract and forward metadata
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		md = metadata.MD{}
	}

	outMD := metadata.MD{}
	for k, v := range md {
		if shouldForwardMetadata(k) {
			outMD[k] = v
		}
	}

	outCtx := metadata.NewOutgoingContext(ctx, outMD)

	d.logger.Debug("directing request to static target",
		observability.String("method", fullMethod),
		observability.String("target", d.target),
	)

	return outCtx, conn, nil
}
