package grpcadapter

import (
	"context"
	"errors"
	"io"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/vyrodovalexey/avapigw/internal/aggregate"
	"github.com/vyrodovalexey/avapigw/internal/config"
	grpcproxy "github.com/vyrodovalexey/avapigw/internal/grpc/proxy"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// streamingUnsupportedMsg is the clear status detail returned when a streaming
// method is invoked with aggregate enabled. gRPC streaming aggregate is a
// documented follow-up (the full interleave/multiplexer transport is not yet
// implemented); aggregate fan-out is supported for UNARY calls only.
const streamingUnsupportedMsg = "gRPC streaming aggregate not supported"

// ProxyHandler implements grpcproxy.GRPCAggregateHandler. It treats an
// aggregate-enabled gRPC call as UNARY: it reads a single request message,
// rejects streaming calls with a clear status, fans the request out across the
// configured targets via a pool-backed Invoker, merges the responses and sends a
// single response message back.
//
// It satisfies grpcproxy.GRPCAggregateHandler so it can be injected into the gRPC
// proxy via grpcproxy.WithAggregateHandler.
type ProxyHandler struct {
	logger  observability.Logger
	metrics *aggregate.Metrics
	tracer  aggregate.Tracer
}

// ProxyHandlerOption configures the ProxyHandler.
type ProxyHandlerOption func(*ProxyHandler)

// WithProxyHandlerMetrics sets the aggregate metrics recorder.
func WithProxyHandlerMetrics(m *aggregate.Metrics) ProxyHandlerOption {
	return func(h *ProxyHandler) {
		if m != nil {
			h.metrics = m
		}
	}
}

// WithProxyHandlerTracer sets the aggregate tracer.
func WithProxyHandlerTracer(t aggregate.Tracer) ProxyHandlerOption {
	return func(h *ProxyHandler) {
		if t != nil {
			h.tracer = t
		}
	}
}

// NewProxyHandler creates a gRPC aggregate proxy handler.
func NewProxyHandler(logger observability.Logger, opts ...ProxyHandlerOption) *ProxyHandler {
	h := &ProxyHandler{
		logger:  observability.NopLogger(),
		metrics: aggregate.NopMetrics(),
		tracer:  aggregate.NopTracer(),
	}
	if logger != nil {
		h.logger = logger
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// HandleAggregate implements grpcproxy.GRPCAggregateHandler. It is invoked by the
// gRPC proxy when a matched route declares an enabled aggregate config.
func (h *ProxyHandler) HandleAggregate(
	_ interface{},
	stream grpc.ServerStream,
	cfg *config.AggregateConfig,
	pool *grpcproxy.ConnectionPool,
) error {
	ctx := stream.Context()
	fullMethod, ok := grpc.Method(ctx)
	if !ok {
		return status.Error(codes.Internal, "failed to get method from context")
	}

	body, serr := receiveUnaryRequest(stream, fullMethod, h.logger)
	if serr != nil {
		return serr
	}

	req := &aggregate.Request{
		Method:  fullMethod,
		Path:    fullMethod,
		Headers: incomingHeaders(ctx),
		Body:    body,
	}

	invoker := NewInvoker(pool, fullMethod, WithInvokerLogger(h.logger))
	unary := NewUnaryHandler(invoker, h.logger, h.metrics, h.tracer)

	out, err := unary.Aggregate(ctx, cfg, req)
	if err != nil {
		return aggregateStatus(err)
	}

	if err := stream.SendMsg(grpcproxy.NewFrame(out.Body)); err != nil {
		h.logger.Warn("failed to send aggregate response",
			observability.String("method", fullMethod),
			observability.Error(err),
		)
		return err
	}
	return nil
}

// receiveUnaryRequest reads a single request message and enforces unary
// semantics. If the client sends a second message (client-streaming), the call
// is rejected with a clear Unimplemented status, since gRPC streaming aggregate
// is a documented follow-up.
func receiveUnaryRequest(
	stream grpc.ServerStream, fullMethod string, logger observability.Logger,
) ([]byte, error) {
	first := grpcproxy.NewFrame(nil)
	if err := stream.RecvMsg(first); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, status.Error(codes.InvalidArgument, "aggregate: empty request stream")
		}
		return nil, err
	}

	// Detect client-streaming: a unary call yields io.EOF on the second receive.
	// Any further message means the method is streaming, which is unsupported.
	second := grpcproxy.NewFrame(nil)
	if err := stream.RecvMsg(second); !errors.Is(err, io.EOF) {
		logger.Warn("gRPC streaming aggregate rejected",
			observability.String("method", fullMethod),
			observability.String("reason", "client_streaming"),
		)
		return nil, status.Error(codes.Unimplemented, streamingUnsupportedMsg)
	}

	return first.Payload(), nil
}

// incomingHeaders extracts inbound gRPC metadata as a forwardable header map,
// dropping pseudo-headers (keys starting with ":") which must not be forwarded
// verbatim to fan-out targets.
func incomingHeaders(ctx context.Context) map[string][]string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil
	}
	out := make(map[string][]string, len(md))
	for k, v := range md {
		if k == "" || k[0] == ':' {
			continue
		}
		cp := make([]string, len(v))
		copy(cp, v)
		out[k] = cp
	}
	return out
}

// aggregateStatus maps an aggregate engine error to a gRPC status. A nil error
// is mapped to OK; ErrNoTargets to FailedPrecondition; all other (FailMode)
// failures to Unavailable.
func aggregateStatus(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, aggregate.ErrNoTargets) {
		return status.Error(codes.FailedPrecondition, "aggregate: no targets configured")
	}
	return status.Error(codes.Unavailable, "aggregate fan-out failed: "+err.Error())
}
