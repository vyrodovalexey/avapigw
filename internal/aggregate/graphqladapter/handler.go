// Package graphqladapter provides a GraphQL adapter for the aggregate fan-out
// engine. It deep-merges data and extensions and concatenates errors across
// targets. It is wired into internal/graphql via an injected interface to avoid
// import cycles.
package graphqladapter

import (
	"io"
	"net/http"

	"github.com/vyrodovalexey/avapigw/internal/aggregate"
	"github.com/vyrodovalexey/avapigw/internal/aggregate/rest"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// maxGraphQLBodyBytes bounds the buffered GraphQL request body for replay.
const maxGraphQLBodyBytes = 10 << 20

// Handler executes a GraphQL aggregate fan-out and writes the merged response.
type Handler struct {
	aggregator aggregate.Aggregator
	merger     *aggregate.Merger
	logger     observability.Logger
}

// NewHandler creates a GraphQL aggregate Handler. When invoker is nil a default
// HTTP invoker is constructed (GraphQL is transported over HTTP POST).
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
		invoker = rest.NewInvoker(rest.WithLogger(logger))
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

// ServeAggregate fans the GraphQL request out per cfg and writes the merged
// GraphQL response (data + extensions deep-merged, errors concatenated).
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
		h.logger.Warn("graphql aggregate fan-out failed", observability.Error(ferr))
		return ferr
	}

	out, merr := h.merger.MergeGraphQL(r.Context(), result.SuccessfulResponses())
	if merr != nil {
		return merr
	}

	w.Header().Set("Content-Type", out.ContentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	//nolint:gosec // G705: body is gateway-generated JSON, content type is fixed application/json (nosniff)
	_, _ = w.Write(out.Body)
	return nil
}

// buildRequest converts an inbound GraphQL HTTP request into an
// aggregate.Request, buffering the body for replay across targets.
func buildRequest(r *http.Request) (*aggregate.Request, error) {
	var body []byte
	if r.Body != nil {
		buffered, err := io.ReadAll(io.LimitReader(r.Body, maxGraphQLBodyBytes))
		if err != nil {
			return nil, err
		}
		body = buffered
	}
	return &aggregate.Request{
		Method:  http.MethodPost,
		Path:    r.URL.RequestURI(),
		Headers: cloneHeaders(r.Header),
		Body:    body,
	}, nil
}

// cloneHeaders copies request headers, dropping headers that must not be
// forwarded verbatim to fan-out targets.
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
