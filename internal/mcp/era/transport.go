package era

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/mcp/jsonrpc"
	mcpproxy "github.com/vyrodovalexey/avapigw/internal/mcp/proxy"
)

// BackendResolver resolves an upstream id to its ServiceBackend and the upstream
// MCP endpoint path. It is satisfied by the gateway MCP handler, decoupling the
// legacy transport from the handler's internals.
type BackendResolver interface {
	// ResolveBackend returns the ServiceBackend and upstream MCP path for
	// upstreamID, or ok=false when the upstream is unknown.
	ResolveBackend(upstreamID string) (sb *backend.ServiceBackend, path string, ok bool)
}

// httpLegacyTransport is the concrete backend-backed LegacyTransport (HUB-701).
// It POSTs legacy JSON-RPC requests and opens the GET SSE stream over the shared
// backend infrastructure (connection pool, TLS/mTLS, per-upstream credentials),
// carrying Mcp-Session-Id and never forwarding a downstream credential upstream
// (HUB-303).
type httpLegacyTransport struct {
	resolver        BackendResolver
	maxResponseSize int64
}

// NewHTTPLegacyTransport constructs the backend-backed legacy transport.
func NewHTTPLegacyTransport(resolver BackendResolver, maxResponseSize int64) LegacyTransport {
	if maxResponseSize <= 0 {
		maxResponseSize = mcpproxy.DefaultMaxResponseSize
	}
	return &httpLegacyTransport{resolver: resolver, maxResponseSize: maxResponseSize}
}

// PostRequest performs a legacy JSON-RPC POST, applying the session header and
// parsing the single JSON response. A 404 (session-not-found) yields
// ErrSessionLost so the session pool re-initializes (HUB-702).
func (t *httpLegacyTransport) PostRequest(
	ctx context.Context, upstreamID string, req *jsonrpc.Request, sessionID string,
) (*jsonrpc.Response, string, error) {
	sb, path, ok := t.resolver.ResolveBackend(upstreamID)
	if !ok {
		return nil, "", fmt.Errorf("era: unknown legacy upstream %q", upstreamID)
	}
	httpReq, host, err := t.buildRequest(ctx, sb, path, req, sessionID)
	if err != nil {
		return nil, "", err
	}
	defer sb.ReleaseHost(host)

	resp, err := sb.HTTPClient().Do(httpReq)
	if err != nil {
		return nil, "", fmt.Errorf("era: legacy upstream request failed: %w", err)
	}
	defer t.drainClose(resp)

	if resp.StatusCode == http.StatusNotFound {
		return nil, "", ErrSessionLost
	}
	newSID := resp.Header.Get(HeaderMcpSessionID)
	parsed, err := t.parseResponse(resp)
	if err != nil {
		return nil, newSID, err
	}
	return parsed, newSID, nil
}

// PostNotification sends a legacy notification (no response body is parsed).
func (t *httpLegacyTransport) PostNotification(
	ctx context.Context, upstreamID string, note *jsonrpc.Request, sessionID string,
) error {
	sb, path, ok := t.resolver.ResolveBackend(upstreamID)
	if !ok {
		return fmt.Errorf("era: unknown legacy upstream %q", upstreamID)
	}
	httpReq, host, err := t.buildRequest(ctx, sb, path, note, sessionID)
	if err != nil {
		return err
	}
	defer sb.ReleaseHost(host)

	resp, err := sb.HTTPClient().Do(httpReq)
	if err != nil {
		return fmt.Errorf("era: legacy notification failed: %w", err)
	}
	t.drainClose(resp)
	if resp.StatusCode == http.StatusNotFound {
		return ErrSessionLost
	}
	return nil
}

// OpenServerStream opens the upstream GET SSE stream for the session and relays
// each event to handler until ctx is canceled or the stream ends (HUB-701). It
// honors Last-Event-ID for best-effort resumption where the upstream supports
// it.
func (t *httpLegacyTransport) OpenServerStream(
	ctx context.Context, upstreamID, sessionID, lastEventID string, handler mcpproxy.SSEEventHandler,
) error {
	sb, path, ok := t.resolver.ResolveBackend(upstreamID)
	if !ok {
		return fmt.Errorf("era: unknown legacy upstream %q", upstreamID)
	}
	host, err := sb.GetAvailableHost()
	if err != nil {
		return fmt.Errorf("era: select legacy host: %w", err)
	}
	defer sb.ReleaseHost(host)

	target := host.URLWithScheme(sb.IsTLSEnabled()) + path
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, target, http.NoBody)
	if err != nil {
		return fmt.Errorf("era: build SSE request: %w", err)
	}
	httpReq.Header.Set("Accept", contentTypeSSE)
	applySessionHeader(httpReq.Header, sessionID)
	if lastEventID != "" {
		// Best-effort resumption where the upstream supports it (HUB-701).
		httpReq.Header.Set(HeaderLastEventID, lastEventID)
	}
	if authErr := sb.ApplyAuth(ctx, httpReq); authErr != nil {
		return fmt.Errorf("era: apply legacy auth: %w", authErr)
	}

	resp, err := sb.HTTPClient().Do(httpReq)
	if err != nil {
		return fmt.Errorf("era: open legacy SSE: %w", err)
	}
	defer t.drainClose(resp)

	if resp.StatusCode == http.StatusNotFound {
		return ErrSessionLost
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("era: legacy SSE status %d", resp.StatusCode)
	}
	return relaySSE(ctx, resp.Body, handler, t.maxResponseSize)
}

// buildRequest constructs a legacy POST with the session header and upstream
// credentials applied, stripping any downstream credential (HUB-303).
func (t *httpLegacyTransport) buildRequest(
	ctx context.Context, sb *backend.ServiceBackend, path string, req *jsonrpc.Request, sessionID string,
) (httpReq *http.Request, host *backend.Host, err error) {
	host, err = sb.GetAvailableHost()
	if err != nil {
		return nil, nil, fmt.Errorf("era: select legacy host: %w", err)
	}
	body, err := jsonrpc.Encode(req)
	if err != nil {
		sb.ReleaseHost(host)
		return nil, nil, fmt.Errorf("era: encode legacy request: %w", err)
	}
	target := host.URLWithScheme(sb.IsTLSEnabled()) + path
	httpReq, err = http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		sb.ReleaseHost(host)
		return nil, nil, fmt.Errorf("era: build legacy request: %w", err)
	}
	httpReq.Header.Set("Content-Type", contentTypeJSON)
	httpReq.Header.Set("Accept", acceptJSONOrSSE)
	applySessionHeader(httpReq.Header, sessionID)
	if authErr := sb.ApplyAuth(ctx, httpReq); authErr != nil {
		sb.ReleaseHost(host)
		return nil, nil, fmt.Errorf("era: apply legacy auth: %w", authErr)
	}
	return httpReq, host, nil
}

// parseResponse reads the bounded response body and parses the JSON-RPC
// response.
func (t *httpLegacyTransport) parseResponse(resp *http.Response) (*jsonrpc.Response, error) {
	limited := io.LimitReader(resp.Body, t.maxResponseSize+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("era: read legacy response: %w", err)
	}
	if int64(len(data)) > t.maxResponseSize {
		return nil, mcpproxy.ErrResponseTooLarge
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, &mcpproxy.UpstreamError{StatusCode: resp.StatusCode, Body: string(data)}
	}
	var rpcResp jsonrpc.Response
	if err := jsonrpc.Decode(data, &rpcResp); err != nil {
		return nil, fmt.Errorf("era: decode legacy response: %w", err)
	}
	return &rpcResp, nil
}

// drainClose drains and closes the response body so the connection can be reused.
func (t *httpLegacyTransport) drainClose(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, t.maxResponseSize))
	_ = resp.Body.Close()
}

// Content-type constants for legacy requests.
const (
	contentTypeJSON = "application/json"
	contentTypeSSE  = "text/event-stream"
	acceptJSONOrSSE = "application/json, text/event-stream"
)
