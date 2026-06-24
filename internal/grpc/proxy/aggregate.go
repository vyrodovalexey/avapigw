package proxy

import (
	"google.golang.org/grpc"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// GRPCAggregateHandler executes a gRPC unary aggregate (fan-out) call for a
// matched route. This interface decouples the gRPC proxy from the
// internal/aggregate engine (mirroring the proxy.AggregateHandler and
// gateway.GraphQLAggregateHandler patterns) to avoid import cycles. The concrete
// implementation is built in cmd/gateway and injected via WithAggregateHandler.
//
// The handler treats the call as UNARY: it receives a single request message
// from the server stream, fans it out to the configured targets in parallel,
// merges (or labeled-envelopes) the responses, and sends a single response
// message back. The proxy's own ConnectionPool is passed in so the handler
// reuses the same pooled, per-target (m)TLS-aware gRPC client connections used
// by normal single-destination proxying.
//
// gRPC STREAMING aggregate is a documented follow-up: when the matched method is
// streaming and aggregate is enabled the handler must fail gracefully with a
// clear codes.Unimplemented/FailedPrecondition status rather than misbehaving.
type GRPCAggregateHandler interface {
	// HandleAggregate fans the unary request out per cfg using the supplied
	// connection pool and writes the aggregated response on the server stream.
	HandleAggregate(
		srv interface{},
		stream grpc.ServerStream,
		cfg *config.AggregateConfig,
		pool *ConnectionPool,
	) error
}

// WithAggregateHandler sets the gRPC aggregate (fan-out) handler. When
// configured and a matched route declares an enabled aggregate config, the unary
// call is fanned out to the configured targets instead of being proxied to a
// single destination.
func WithAggregateHandler(h GRPCAggregateHandler) ProxyOption {
	return func(p *Proxy) {
		p.aggregateHandler = h
	}
}

// handleAggregate routes a matched aggregate-enabled unary call to the injected
// aggregate handler. It returns (handled, err): handled is true when the
// aggregate handler took ownership of the stream (success or terminal error), in
// which case the caller must not perform normal single-destination proxying.
//
// When no aggregate handler is injected or the route does not declare an enabled
// aggregate config, handled is false and normal proxying proceeds unchanged
// (no regression to non-aggregate gRPC traffic).
func (p *Proxy) handleAggregate(
	srv interface{},
	stream grpc.ServerStream,
	fullMethod string,
	routeCfg *config.GRPCRoute,
) (handled bool, err error) {
	if p.aggregateHandler == nil || !routeCfg.Aggregate.IsEnabled() {
		return false, nil
	}

	p.logger.Debug("handling gRPC aggregate fan-out",
		observability.String("method", fullMethod),
		observability.String("route", routeCfg.Name),
	)

	aggErr := p.aggregateHandler.HandleAggregate(srv, stream, routeCfg.Aggregate, p.connPool)
	if aggErr != nil {
		p.logger.Warn("gRPC aggregate fan-out failed",
			observability.String("method", fullMethod),
			observability.String("route", routeCfg.Name),
			observability.Error(aggErr),
		)
	}
	return true, aggErr
}
