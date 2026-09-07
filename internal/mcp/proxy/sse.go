package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/mcp/jsonrpc"
)

// SSE content type and field prefixes (WHATWG server-sent events).
const (
	// contentTypeSSE is the SSE media type advertised on a stream response.
	contentTypeSSE = "text/event-stream"

	sseFieldEvent   = "event:"
	sseFieldData    = "data:"
	sseFieldComment = ":"
)

// ErrSSEEventTooLarge indicates a single SSE event exceeded the configured
// maximum event size (HUB-405).
var ErrSSEEventTooLarge = errors.New("mcp proxy: SSE event too large")

// SSEEvent is a decoded server-sent event: its event name (may be empty) and
// the concatenated data payload with the trailing newline removed.
type SSEEvent struct {
	// Event is the SSE event name (the "event:" field), or "" when unset.
	Event string
	// Data is the concatenated "data:" payload for the event.
	Data []byte
}

// SSEWriter originates or relays SSE events to a downstream sink. It abstracts
// the concrete downstream response writer so the relay code is transport
// agnostic and testable.
type SSEWriter interface {
	// WriteEvent writes a single named SSE event with the given data payload.
	// An empty event name omits the "event:" line.
	WriteEvent(event string, data []byte) error
	// WriteComment writes an SSE comment line (":<c>"), used for keep-alive.
	WriteComment(c string) error
	// Flush flushes any buffered bytes to the underlying transport.
	Flush() error
}

// SSEEventHandler is invoked for each event relayed from an upstream stream.
// Returning an error stops the relay and is propagated to the Stream caller.
type SSEEventHandler func(ev SSEEvent) error

// Stream forwards a single JSON-RPC request to the upstream and relays the
// response as a sequence of SSE events (HUB-244). When the upstream answers
// with text/event-stream, every parsed event is delivered to handler in order;
// when it answers with application/json, the single JSON body is delivered as
// one event (event name "message") and the stream closes. The relay stops and
// the upstream connection is closed as soon as ctx is canceled (HUB-241/242).
func (c *HTTPHubClient) Stream(
	ctx context.Context,
	up *backend.ServiceBackend,
	upstreamPath string,
	req *jsonrpc.Request,
	upstreamHeaders http.Header,
	handler SSEEventHandler,
) error {
	if up == nil {
		return ErrNilUpstream
	}
	if req == nil {
		return ErrNilRequest
	}
	if handler == nil {
		return errors.New("mcp proxy: nil SSE handler")
	}

	ctx, span := startUpstreamSpan(ctx, "mcp.upstream.stream", up.Name(), req.Method)
	defer span.End()

	httpReq, host, err := c.buildRequest(ctx, up, upstreamPath, req, upstreamHeaders)
	if err != nil {
		return err
	}
	defer up.ReleaseHost(host)

	resp, err := up.HTTPClient().Do(httpReq)
	if err != nil {
		return fmt.Errorf("mcp proxy: upstream stream request failed: %w", err)
	}
	defer func() {
		// Draining is bounded; on cancellation the body is closed to stop
		// the upstream stream (HUB-242).
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, c.maxResponseSize))
		_ = resp.Body.Close()
	}()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, c.maxSSEEventSize))
		return &UpstreamError{StatusCode: resp.StatusCode, Body: string(body)}
	}

	if isSSEResponse(resp) {
		return c.relaySSE(ctx, resp.Body, handler)
	}
	return c.relaySingleJSON(resp, handler)
}

// isSSEResponse reports whether the upstream response is an SSE stream.
func isSSEResponse(resp *http.Response) bool {
	ct := resp.Header.Get("Content-Type")
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(ct)), contentTypeSSE)
}

// relaySingleJSON delivers a single JSON body as one SSE event and closes.
func (c *HTTPHubClient) relaySingleJSON(resp *http.Response, handler SSEEventHandler) error {
	limited := io.LimitReader(resp.Body, c.maxResponseSize+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("mcp proxy: read upstream response: %w", err)
	}
	if int64(len(data)) > c.maxResponseSize {
		return ErrResponseTooLarge
	}
	return handler(SSEEvent{Event: eventNameMessage, Data: data})
}

// eventNameMessage is the default SSE event name for MCP JSON-RPC payloads.
const eventNameMessage = "message"

// relaySSE reads SSE events from r and delivers each to handler until EOF, ctx
// cancellation or a handler/decoder error. It enforces the max SSE event size
// (HUB-405) and stops promptly when ctx is canceled (HUB-241/242).
func (c *HTTPHubClient) relaySSE(ctx context.Context, r io.Reader, handler SSEEventHandler) error {
	scanner := bufio.NewScanner(r)
	// Bound each scanned line and the accumulated event to the SSE event
	// limit so a hostile upstream cannot exhaust memory (HUB-405).
	maxEvent := int(c.maxSSEEventSize)
	scanner.Buffer(make([]byte, 0, sseInitialBuf), maxEvent+1)

	var (
		eventName string
		dataBuf   bytes.Buffer
	)

	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("mcp proxy: stream canceled: %w", err)
		}
		line := scanner.Bytes()
		if len(line) == 0 {
			// Blank line dispatches the accumulated event.
			if err := c.dispatchEvent(&eventName, &dataBuf, handler); err != nil {
				return err
			}
			continue
		}
		if err := appendSSEField(line, &eventName, &dataBuf, maxEvent); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return ErrSSEEventTooLarge
		}
		return fmt.Errorf("mcp proxy: read upstream SSE: %w", err)
	}
	// Dispatch any trailing event not terminated by a blank line.
	return c.dispatchEvent(&eventName, &dataBuf, handler)
}

// sseInitialBuf is the initial per-line scanner buffer size.
const sseInitialBuf = 4096

// dispatchEvent delivers the accumulated event to handler and resets the
// accumulators. An event with no data is ignored (comment-only frames).
func (c *HTTPHubClient) dispatchEvent(
	eventName *string, dataBuf *bytes.Buffer, handler SSEEventHandler,
) error {
	if dataBuf.Len() == 0 {
		*eventName = ""
		return nil
	}
	name := *eventName
	if name == "" {
		name = eventNameMessage
	}
	data := append([]byte(nil), dataBuf.Bytes()...)
	*eventName = ""
	dataBuf.Reset()
	return handler(SSEEvent{Event: name, Data: data})
}

// appendSSEField parses one non-blank SSE line, updating the event name or
// appending to the data buffer, bounding the accumulated data (HUB-405).
func appendSSEField(line []byte, eventName *string, dataBuf *bytes.Buffer, maxEvent int) error {
	switch {
	case bytes.HasPrefix(line, []byte(sseFieldEvent)):
		*eventName = strings.TrimSpace(string(line[len(sseFieldEvent):]))
	case bytes.HasPrefix(line, []byte(sseFieldData)):
		val := bytes.TrimPrefix(line[len(sseFieldData):], []byte(" "))
		if dataBuf.Len()+len(val)+1 > maxEvent {
			return ErrSSEEventTooLarge
		}
		if dataBuf.Len() > 0 {
			dataBuf.WriteByte('\n')
		}
		dataBuf.Write(val)
	case bytes.HasPrefix(line, []byte(sseFieldComment)):
		// Comment / keep-alive line: ignored on the upstream side.
	default:
		// Unknown field (id:, retry:, ...): ignored. The hub does not
		// resume streams (HUB-105) so id/retry carry no meaning.
	}
	return nil
}
