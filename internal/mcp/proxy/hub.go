// Package proxy implements the MCP hub's upstream client: it forwards a single
// JSON-RPC request to a selected HTTP(S) MCP upstream (Streamable HTTP
// transport) and parses the single JSON response, or relays the response as a
// sequence of server-sent events (SSE) for streaming methods (HUB-241/244).
// Discovery aggregation, caching and MRTR are handled elsewhere; this client
// covers the request/response and SSE-relay broker paths (HUB-241/303/405).
package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/mcp/jsonrpc"
	"github.com/vyrodovalexey/avapigw/internal/mcp/lifecycle"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// ProgressSink receives a raw notifications/progress payload to relay on the
// downstream response stream (HUB-244). It is attached to the call context by
// the broker so Call can relay progress from an SSE-typed upstream response
// without changing its signature.
type ProgressSink func(raw []byte)

// progressSinkCtxKey is the context key for the ProgressSink.
type progressSinkCtxKey struct{}

// WithProgressSink returns a context carrying sink so an SSE-typed tools/call
// upstream response relays notifications/progress downstream (HUB-244).
func WithProgressSink(ctx context.Context, sink ProgressSink) context.Context {
	if sink == nil {
		return ctx
	}
	return context.WithValue(ctx, progressSinkCtxKey{}, sink)
}

// progressSinkFromContext returns the ProgressSink attached to ctx, or nil.
func progressSinkFromContext(ctx context.Context) ProgressSink {
	sink, _ := ctx.Value(progressSinkCtxKey{}).(ProgressSink)
	return sink
}

// hubTracerName is the OTLP tracer name for the MCP upstream client spans
// (T-62). It matches the downstream server span tracer so both appear under the
// same instrumentation scope.
const hubTracerName = "avapigw/mcp"

// DefaultMaxResponseSize bounds a single upstream JSON response when no limit
// is configured (HUB-405). It mirrors config.DefaultMCPMaxResponseSize.
const DefaultMaxResponseSize int64 = 16 * 1024 * 1024

// DefaultMaxSSEEventSize bounds a single relayed/originated SSE event when no
// limit is configured (HUB-405). It mirrors config.DefaultMCPMaxSSEEventSize.
const DefaultMaxSSEEventSize int64 = 1 * 1024 * 1024

// Content-type / accept constants used on upstream requests.
const (
	contentTypeJSON = "application/json"
	// acceptTypes advertises both JSON and SSE so a modern upstream may
	// answer with either; the JSON path is handled here (SSE relay is M4).
	acceptTypes = "application/json, text/event-stream"
)

// Sentinel errors returned by the hub client.
var (
	// ErrNilUpstream indicates a nil upstream backend was supplied.
	ErrNilUpstream = errors.New("mcp proxy: nil upstream backend")
	// ErrNilRequest indicates a nil JSON-RPC request was supplied.
	ErrNilRequest = errors.New("mcp proxy: nil jsonrpc request")
	// ErrResponseTooLarge indicates the upstream response exceeded the
	// configured maximum size (HUB-405).
	ErrResponseTooLarge = errors.New("mcp proxy: upstream response too large")
)

// UpstreamError wraps a non-2xx HTTP status returned by an upstream so callers
// can distinguish transport-level failures from protocol-level JSON-RPC
// errors.
type UpstreamError struct {
	// StatusCode is the HTTP status returned by the upstream.
	StatusCode int
	// Body is a bounded snippet of the upstream response body.
	Body string
}

// Error implements the error interface.
func (e *UpstreamError) Error() string {
	return fmt.Sprintf("mcp proxy: upstream returned HTTP %d", e.StatusCode)
}

// HubClient forwards a single JSON-RPC request to an MCP upstream and returns
// the parsed response, or relays the response as SSE events for streaming
// methods.
type HubClient interface {
	// Call forwards req to up at upstreamPath, applying the supplied
	// re-derived Mcp-* headers and the upstream's own credentials, and
	// returns the parsed single JSON-RPC response.
	Call(
		ctx context.Context,
		up *backend.ServiceBackend,
		upstreamPath string,
		req *jsonrpc.Request,
		upstreamHeaders http.Header,
	) (*jsonrpc.Response, error)

	// Stream forwards req to up at upstreamPath and relays the response as a
	// sequence of SSE events, invoking handler for each. A single-JSON
	// upstream response is delivered as one event. The relay stops when ctx
	// is canceled (HUB-241/242/244).
	Stream(
		ctx context.Context,
		up *backend.ServiceBackend,
		upstreamPath string,
		req *jsonrpc.Request,
		upstreamHeaders http.Header,
		handler SSEEventHandler,
	) error
}

// HTTPHubClient is the default HTTP(S) HubClient. It reuses the shared backend
// infrastructure (connection pool, TLS/mTLS, per-backend credentials) via the
// ServiceBackend passed to Call.
type HTTPHubClient struct {
	logger          observability.Logger
	maxResponseSize int64
	maxSSEEventSize int64
}

// HubClientOption is a functional option for HTTPHubClient.
type HubClientOption func(*HTTPHubClient)

// WithHubClientLogger sets the client logger.
func WithHubClientLogger(logger observability.Logger) HubClientOption {
	return func(c *HTTPHubClient) {
		if logger != nil {
			c.logger = logger
		}
	}
}

// WithHubClientMaxResponseSize sets the maximum upstream response size in
// bytes. Non-positive values are ignored.
func WithHubClientMaxResponseSize(limit int64) HubClientOption {
	return func(c *HTTPHubClient) {
		if limit > 0 {
			c.maxResponseSize = limit
		}
	}
}

// WithHubClientMaxSSEEventSize sets the maximum relayed/originated SSE event
// size in bytes (HUB-405). Non-positive values are ignored.
func WithHubClientMaxSSEEventSize(limit int64) HubClientOption {
	return func(c *HTTPHubClient) {
		if limit > 0 {
			c.maxSSEEventSize = limit
		}
	}
}

// NewHTTPHubClient constructs an HTTPHubClient with the given options.
func NewHTTPHubClient(opts ...HubClientOption) *HTTPHubClient {
	c := &HTTPHubClient{
		logger:          observability.NopLogger(),
		maxResponseSize: DefaultMaxResponseSize,
		maxSSEEventSize: DefaultMaxSSEEventSize,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Call forwards a single JSON-RPC request to the upstream (HUB-241). It selects
// an available host from the backend, builds an HTTP POST with the marshaled
// request body, applies the re-derived Mcp-* headers and the upstream's own
// credentials (no downstream token passthrough, HUB-303), and parses the
// single JSON response bounded by the configured maximum size (HUB-405).
func (c *HTTPHubClient) Call(
	ctx context.Context,
	up *backend.ServiceBackend,
	upstreamPath string,
	req *jsonrpc.Request,
	upstreamHeaders http.Header,
) (*jsonrpc.Response, error) {
	if up == nil {
		return nil, ErrNilUpstream
	}
	if req == nil {
		return nil, ErrNilRequest
	}

	ctx, span := startUpstreamSpan(ctx, "mcp.upstream.call", up.Name(), req.Method)
	defer span.End()

	httpReq, host, err := c.buildRequest(ctx, up, upstreamPath, req, upstreamHeaders)
	if err != nil {
		return nil, err
	}
	// Return the host to the pool once the round-trip completes.
	defer up.ReleaseHost(host)

	resp, err := up.HTTPClient().Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("mcp proxy: upstream request failed: %w", err)
	}
	defer func() {
		// Drain and close so the connection can be reused.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, c.maxResponseSize))
		_ = resp.Body.Close()
	}()

	// A modern upstream may answer a single tools/call with either JSON or an
	// SSE stream that interleaves notifications/progress before the terminal
	// result (HUB-244). Detect the SSE form and parse it, relaying progress on
	// the response stream via the context-scoped sink; otherwise decode the
	// single JSON response.
	if isSSEResponse(resp) {
		return c.parseSSEResponse(ctx, resp)
	}
	return c.parseResponse(resp)
}

// parseSSEResponse consumes an SSE-typed upstream tools/call response
// (HUB-244): it relays every notifications/progress event to the
// context-scoped ProgressSink (preserving progressToken semantics) and returns
// the terminal JSON-RPC response event. A non-2xx status yields an
// *UpstreamError.
func (c *HTTPHubClient) parseSSEResponse(ctx context.Context, resp *http.Response) (*jsonrpc.Response, error) {
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, c.maxSSEEventSize))
		return nil, &UpstreamError{StatusCode: resp.StatusCode, Body: string(body)}
	}

	sink := progressSinkFromContext(ctx)
	var terminal *jsonrpc.Response
	err := c.relaySSE(ctx, resp.Body, func(ev SSEEvent) error {
		resp, notif := classifySSEEvent(ev.Data)
		switch {
		case notif != nil:
			// Relay a progress notification on the response stream; other
			// notifications on a tools/call stream are dropped (HUB-227).
			if sink != nil && lifecycle.IsProgress(notif.Method) {
				sink(ev.Data)
			}
		case resp != nil:
			terminal = resp
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if terminal == nil {
		return nil, fmt.Errorf("mcp proxy: SSE stream ended without a terminal response")
	}
	return terminal, nil
}

// classifySSEEvent decodes an SSE event payload as either a JSON-RPC response
// (carrying result or error) or a notification (a request without an id). A
// payload that is neither yields two nils and is ignored.
func classifySSEEvent(data []byte) (*jsonrpc.Response, *jsonrpc.Request) {
	var probe struct {
		Method string          `json:"method"`
		ID     json.RawMessage `json:"id"`
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, nil
	}
	if probe.Method != "" {
		var req jsonrpc.Request
		if err := jsonrpc.Decode(data, &req); err != nil {
			return nil, nil
		}
		return nil, &req
	}
	if len(probe.Result) > 0 || len(probe.Error) > 0 {
		var resp jsonrpc.Response
		if err := jsonrpc.Decode(data, &resp); err != nil {
			return nil, nil
		}
		return &resp, nil
	}
	return nil, nil
}

// buildRequest selects a host, marshals the body, and constructs the upstream
// HTTP POST with headers and credentials applied. The selected host is
// returned so the caller can release it after the round-trip.
func (c *HTTPHubClient) buildRequest(
	ctx context.Context,
	up *backend.ServiceBackend,
	upstreamPath string,
	req *jsonrpc.Request,
	upstreamHeaders http.Header,
) (httpReq *http.Request, host *backend.Host, err error) {
	host, err = up.GetAvailableHost()
	if err != nil {
		return nil, nil, fmt.Errorf("mcp proxy: select upstream host: %w", err)
	}

	body, err := jsonrpc.Encode(req)
	if err != nil {
		up.ReleaseHost(host)
		return nil, nil, fmt.Errorf("mcp proxy: encode request: %w", err)
	}

	target := host.URLWithScheme(up.IsTLSEnabled()) + upstreamPath
	httpReq, err = http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		up.ReleaseHost(host)
		return nil, nil, fmt.Errorf("mcp proxy: build upstream request: %w", err)
	}

	c.applyHeaders(httpReq, upstreamHeaders)

	// Inject the active trace context into the upstream request so the child
	// span links to the hub's downstream span (T-62). Mirrors proxy.doProxy.
	// ctx already carries the upstream span started by Call/Stream.
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(httpReq.Header))

	// Apply the upstream's own credentials. The downstream client token is
	// never forwarded (HUB-303).
	if authErr := up.ApplyAuth(ctx, httpReq); authErr != nil {
		up.ReleaseHost(host)
		return nil, nil, fmt.Errorf("mcp proxy: apply upstream auth: %w", authErr)
	}

	return httpReq, host, nil
}

// applyHeaders sets the MCP content negotiation headers and copies the
// re-derived Mcp-* headers onto the upstream request. It strips any inherited
// downstream Authorization/Cookie credentials before the upstream's own
// credentials are applied, so the downstream client token is never forwarded
// upstream (HUB-303/308: token passthrough is a defect).
func (c *HTTPHubClient) applyHeaders(httpReq *http.Request, upstreamHeaders http.Header) {
	httpReq.Header.Set("Content-Type", contentTypeJSON)
	httpReq.Header.Set("Accept", acceptTypes)
	for key, values := range upstreamHeaders {
		if isDownstreamCredentialHeader(key) {
			continue // never propagate a downstream credential upstream
		}
		for _, v := range values {
			httpReq.Header.Add(key, v)
		}
	}
	stripDownstreamCredentials(httpReq.Header)
}

// downstreamCredentialHeaders are request headers that carry the downstream
// client's credentials and MUST NOT be forwarded to an upstream (HUB-303).
var downstreamCredentialHeaders = []string{"Authorization", "Cookie", "Proxy-Authorization"}

// isDownstreamCredentialHeader reports whether a header name (in any case)
// carries a downstream credential.
func isDownstreamCredentialHeader(name string) bool {
	for _, h := range downstreamCredentialHeaders {
		if strings.EqualFold(name, h) {
			return true
		}
	}
	return false
}

// stripDownstreamCredentials removes every downstream credential header from
// the outgoing upstream request as a defense-in-depth guard before the
// upstream's own credentials are applied (HUB-303).
func stripDownstreamCredentials(h http.Header) {
	for _, name := range downstreamCredentialHeaders {
		h.Del(name)
	}
}

// parseResponse reads the bounded response body and parses the single JSON-RPC
// response. A non-2xx status yields an *UpstreamError.
func (c *HTTPHubClient) parseResponse(resp *http.Response) (*jsonrpc.Response, error) {
	limited := io.LimitReader(resp.Body, c.maxResponseSize+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("mcp proxy: read upstream response: %w", err)
	}
	if int64(len(data)) > c.maxResponseSize {
		return nil, ErrResponseTooLarge
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, &UpstreamError{StatusCode: resp.StatusCode, Body: string(data)}
	}

	var rpcResp jsonrpc.Response
	if err := jsonrpc.Decode(data, &rpcResp); err != nil {
		return nil, fmt.Errorf("mcp proxy: decode upstream response: %w", err)
	}
	return &rpcResp, nil
}

// startUpstreamSpan starts a client span for a single upstream MCP call/stream
// and stamps the upstream/method attributes (T-62). The returned context
// carries the span so trace context can be injected into upstream headers.
func startUpstreamSpan(
	ctx context.Context, name, upstream, method string,
) (context.Context, trace.Span) {
	tracer := otel.Tracer(hubTracerName)
	return tracer.Start(ctx, name,
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("mcp.upstream", upstream),
			attribute.String("mcp.method", method),
		),
	)
}
