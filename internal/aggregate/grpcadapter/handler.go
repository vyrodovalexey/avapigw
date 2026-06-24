// Package grpcadapter provides a gRPC adapter for the aggregate fan-out engine.
//
// For unary calls it produces a descriptor-based JSON merge when the caller's
// Invoker yields JSON-mappable responses, otherwise it falls back to a
// labeled-envelope concat (last-wins semantics are available via the replace
// merge strategy). It is wired into internal/grpc via an injected interface to
// avoid import cycles. Per-target mTLS and OIDC are honored by the injected
// Invoker.
package grpcadapter

import (
	"context"

	"github.com/vyrodovalexey/avapigw/internal/aggregate"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// UnaryHandler executes a gRPC unary aggregate fan-out.
type UnaryHandler struct {
	aggregator aggregate.Aggregator
	merger     *aggregate.Merger
	logger     observability.Logger
}

// NewUnaryHandler creates a gRPC unary aggregate handler. The Invoker must be
// supplied by the caller (internal/grpc) since gRPC transport is descriptor- and
// connection-pool-specific.
func NewUnaryHandler(
	invoker aggregate.Invoker,
	logger observability.Logger,
	metrics *aggregate.Metrics,
	tracer aggregate.Tracer,
) *UnaryHandler {
	if logger == nil {
		logger = observability.NopLogger()
	}
	return &UnaryHandler{
		aggregator: aggregate.NewAggregator(invoker,
			aggregate.WithLogger(logger),
			aggregate.WithMetrics(metrics),
			aggregate.WithTracer(tracer),
		),
		merger: aggregate.NewMerger(logger, metrics, tracer),
		logger: logger,
	}
}

// Aggregate fans the unary request out per cfg and returns the combined response
// body. When cfg.Merge is enabled and target payloads are JSON-mappable, a true
// merge is produced; otherwise a labeled envelope is returned.
func (h *UnaryHandler) Aggregate(
	ctx context.Context,
	cfg *config.AggregateConfig,
	req *aggregate.Request,
) (*aggregate.MergeOutput, error) {
	runtimeCfg := aggregate.FromConfig(cfg)
	if runtimeCfg == nil {
		return nil, aggregate.ErrNoTargets
	}

	result, err := h.aggregator.Fanout(ctx, runtimeCfg, req)
	if err != nil {
		h.logger.Warn("grpc aggregate fan-out failed", observability.Error(err))
		return nil, err
	}

	return h.merger.Combine(ctx, runtimeCfg.Merge, result.SuccessfulResponses())
}
