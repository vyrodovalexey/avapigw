package proxy

import (
	"context"
	"fmt"
	"math/rand"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/grpc/router"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// Director determines the backend destination for a gRPC request.
type Director interface {
	// Direct returns the backend connection and context for a request.
	Direct(ctx context.Context, fullMethod string) (context.Context, *grpc.ClientConn, error)
}

// RouterDirector uses the gRPC router to determine backend destinations.
type RouterDirector struct {
	router   *router.Router
	connPool *ConnectionPool
	logger   observability.Logger
	counter  atomic.Uint64 // for round-robin selection
}

// DirectorOption is a functional option for configuring the director.
type DirectorOption func(*RouterDirector)

// WithDirectorLogger sets the logger for the director.
func WithDirectorLogger(logger observability.Logger) DirectorOption {
	return func(d *RouterDirector) {
		d.logger = logger
	}
}

// NewRouterDirector creates a new router-based director.
func NewRouterDirector(r *router.Router, pool *ConnectionPool, opts ...DirectorOption) *RouterDirector {
	d := &RouterDirector{
		router:   r,
		connPool: pool,
		logger:   observability.NopLogger(),
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

	// Select destination
	dest := d.selectDestination(result.Route.Config.Route)
	if dest == nil {
		metrics.directRequests.WithLabelValues(fullMethod, "no_destination").Inc()
		metrics.directDuration.WithLabelValues(fullMethod).Observe(time.Since(start).Seconds())
		return ctx, nil, fmt.Errorf("no destination available for route %s", result.Route.Name)
	}

	// Build target address
	target := fmt.Sprintf("%s:%d", dest.Destination.Host, dest.Destination.Port)

	// Record backend selection decision
	selectionStrategy := "weighted"
	if len(result.Route.Config.Route) == 1 {
		selectionStrategy = "single"
	}
	metrics.backendSelections.WithLabelValues(
		result.Route.Name, target, selectionStrategy,
	).Inc()

	// Get connection from pool
	conn, err := d.connPool.Get(ctx, target)
	if err != nil {
		d.logger.Error("failed to get connection",
			observability.String("target", target),
			observability.Error(err),
		)
		metrics.directRequests.WithLabelValues(fullMethod, "connection_error").Inc()
		metrics.directDuration.WithLabelValues(fullMethod).Observe(time.Since(start).Seconds())
		return ctx, nil, fmt.Errorf("failed to connect to %s: %w", target, err)
	}

	// Create outgoing context with metadata
	outCtx := d.createOutgoingContext(ctx, md, result.Route.Name)

	metrics.directRequests.WithLabelValues(fullMethod, "success").Inc()
	metrics.directDuration.WithLabelValues(fullMethod).Observe(time.Since(start).Seconds())

	d.logger.Debug("directing request",
		observability.String("method", fullMethod),
		observability.String("route", result.Route.Name),
		observability.String("target", target),
	)

	return outCtx, conn, nil
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
func (d *RouterDirector) createOutgoingContext(
	ctx context.Context, inMD metadata.MD, routeName string,
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

	return metadata.NewOutgoingContext(ctx, outMD)
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
