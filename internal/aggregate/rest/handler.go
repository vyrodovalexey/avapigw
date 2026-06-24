package rest

import (
	"context"
	"io"
	"net/http"

	"github.com/vyrodovalexey/avapigw/internal/aggregate"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// maxAggregateBodyBytes bounds how much of the client request body is buffered
// for fan-out replay (10MB, matching the default request-limit).
const maxAggregateBodyBytes = 10 << 20

// Handler executes a REST aggregate fan-out for a request and writes the
// aggregated (merged or labeled-envelope) response.
type Handler struct {
	aggregator aggregate.Aggregator
	merger     *aggregate.Merger
	logger     observability.Logger
}

// NewHandler creates a REST aggregate Handler. When invoker is nil a default
// HTTP invoker is constructed.
func NewHandler(
	invoker aggregate.Invoker,
	logger observability.Logger,
	metrics *aggregate.Metrics,
	tracer aggregate.Tracer,
) *Handler {
	if logger == nil {
		logger = observability.NopLogger()
	}
	if invoker == nil {
		invoker = NewInvoker(WithLogger(logger))
	}
	return &Handler{
		aggregator: aggregate.NewAggregator(invoker,
			aggregate.WithLogger(logger),
			aggregate.WithMetrics(metrics),
			aggregate.WithTracer(tracer),
		),
		merger: aggregate.NewMerger(logger, metrics, tracer),
		logger: logger,
	}
}

// ServeAggregate fans the request out per cfg and writes the aggregated
// response. It returns an error only when fan-out cannot satisfy the configured
// FailMode; in that case no response has been written and the caller may emit an
// error status.
func (h *Handler) ServeAggregate(
	w http.ResponseWriter,
	r *http.Request,
	cfg *config.AggregateConfig,
) error {
	runtimeCfg := aggregate.FromConfig(cfg)
	if runtimeCfg == nil {
		return aggregate.ErrNoTargets
	}

	req, err := buildRequest(r)
	if err != nil {
		return err
	}

	result, ferr := h.aggregator.Fanout(r.Context(), runtimeCfg, req)
	if ferr != nil {
		h.logger.Warn("aggregate fan-out failed", observability.Error(ferr))
		return ferr
	}

	out, merr := h.combine(r.Context(), runtimeCfg, result)
	if merr != nil {
		return merr
	}

	writeResponse(w, out)
	return nil
}

// combine merges the successful responses according to the runtime config.
func (h *Handler) combine(
	ctx context.Context,
	cfg *aggregate.Config,
	result *aggregate.Result,
) (*aggregate.MergeOutput, error) {
	return h.merger.Combine(ctx, cfg.Merge, result.SuccessfulResponses())
}

// buildRequest converts an inbound HTTP request into an aggregate.Request,
// buffering the body for replay across targets.
func buildRequest(r *http.Request) (*aggregate.Request, error) {
	var body []byte
	if r.Body != nil {
		limited := io.LimitReader(r.Body, maxAggregateBodyBytes)
		buffered, err := io.ReadAll(limited)
		if err != nil {
			return nil, err
		}
		body = buffered
	}
	return &aggregate.Request{
		Method:  r.Method,
		Path:    r.URL.RequestURI(),
		Headers: cloneHeaders(r.Header),
		Body:    body,
	}, nil
}

// cloneHeaders copies request headers, dropping hop-by-hop and host headers that
// must not be forwarded verbatim to fan-out targets.
func cloneHeaders(src http.Header) map[string][]string {
	out := make(map[string][]string, len(src))
	for name, values := range src {
		switch http.CanonicalHeaderKey(name) {
		case "Host", "Connection", "Content-Length", "Transfer-Encoding":
			continue
		default:
			cp := make([]string, len(values))
			copy(cp, values)
			out[name] = cp
		}
	}
	return out
}

// writeResponse writes the aggregated body to the client. The body is a JSON
// document produced by the merger and the content type is fixed to
// application/json with nosniff, so it is not attacker-controlled markup.
func writeResponse(w http.ResponseWriter, out *aggregate.MergeOutput) {
	w.Header().Set("Content-Type", out.ContentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	//nolint:gosec // G705: body is gateway-generated JSON, content type is fixed application/json (nosniff)
	_, _ = w.Write(out.Body)
}
