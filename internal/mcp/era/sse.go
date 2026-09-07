package era

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"

	mcpproxy "github.com/vyrodovalexey/avapigw/internal/mcp/proxy"
)

// SSE field prefixes (WHATWG server-sent events).
const (
	sseFieldEvent = "event:"
	sseFieldData  = "data:"

	// sseInitialBuf is the initial per-line scanner buffer size.
	sseInitialBuf = 4096
	// eventNameMessage is the default SSE event name for JSON-RPC payloads.
	eventNameMessage = "message"
)

// relaySSE reads SSE events from r and delivers each to handler until EOF, ctx
// cancellation, or a handler/decoder error (HUB-701 legacy SSE pump). It bounds
// the accumulated event to maxEvent so a hostile upstream cannot exhaust memory
// and exits promptly when ctx is canceled (goroutine-leak guard).
func relaySSE(ctx context.Context, r io.Reader, handler mcpproxy.SSEEventHandler, maxEvent int64) error {
	scanner := bufio.NewScanner(r)
	limit := int(maxEvent)
	scanner.Buffer(make([]byte, 0, sseInitialBuf), limit+1)

	var (
		eventName string
		dataBuf   bytes.Buffer
	)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("era: legacy SSE canceled: %w", err)
		}
		line := scanner.Bytes()
		if len(line) == 0 {
			if err := dispatchEvent(&eventName, &dataBuf, handler); err != nil {
				return err
			}
			continue
		}
		appendSSEField(line, &eventName, &dataBuf)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("era: read legacy SSE: %w", err)
	}
	return dispatchEvent(&eventName, &dataBuf, handler)
}

// dispatchEvent delivers the accumulated event to handler and resets the
// accumulators. An event with no data is ignored (comment-only frames).
func dispatchEvent(eventName *string, dataBuf *bytes.Buffer, handler mcpproxy.SSEEventHandler) error {
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
	return handler(mcpproxy.SSEEvent{Event: name, Data: data})
}

// appendSSEField parses one non-blank SSE line, updating the event name or
// appending to the data buffer.
func appendSSEField(line []byte, eventName *string, dataBuf *bytes.Buffer) {
	switch {
	case bytes.HasPrefix(line, []byte(sseFieldEvent)):
		*eventName = strings.TrimSpace(string(line[len(sseFieldEvent):]))
	case bytes.HasPrefix(line, []byte(sseFieldData)):
		val := bytes.TrimPrefix(line[len(sseFieldData):], []byte(" "))
		if dataBuf.Len() > 0 {
			dataBuf.WriteByte('\n')
		}
		dataBuf.Write(val)
	default:
		// id:, retry:, comment lines: ignored. Last-Event-ID resumption is
		// best-effort and not tracked per-frame here (HUB-701).
	}
}
