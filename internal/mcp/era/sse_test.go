package era

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	mcpproxy "github.com/vyrodovalexey/avapigw/internal/mcp/proxy"
)

const testMaxEvent = 1 << 20

func collectSSE(t *testing.T, ctx context.Context, r io.Reader) ([]mcpproxy.SSEEvent, error) {
	t.Helper()
	var events []mcpproxy.SSEEvent
	err := relaySSE(ctx, r, func(ev mcpproxy.SSEEvent) error {
		events = append(events, ev)
		return nil
	}, testMaxEvent)
	return events, err
}

func TestRelaySSESingleEvent(t *testing.T) {
	t.Parallel()
	events, err := collectSSE(t, context.Background(),
		strings.NewReader("event: message\ndata: {\"x\":1}\n\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("got %d events want 1", len(events))
	}
	if events[0].Event != "message" || string(events[0].Data) != `{"x":1}` {
		t.Fatalf("event = %+v", events[0])
	}
}

func TestRelaySSEDefaultEventName(t *testing.T) {
	t.Parallel()
	events, err := collectSSE(t, context.Background(), strings.NewReader("data: {\"x\":1}\n\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Event != "message" {
		t.Fatalf("expected default event name 'message', got %+v", events)
	}
}

func TestRelaySSEMultiLineData(t *testing.T) {
	t.Parallel()
	events, err := collectSSE(t, context.Background(), strings.NewReader("data: a\ndata: b\n\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || string(events[0].Data) != "a\nb" {
		t.Fatalf("multi-line data not joined: %+v", events)
	}
}

func TestRelaySSEIgnoredLines(t *testing.T) {
	t.Parallel()
	events, err := collectSSE(t, context.Background(),
		strings.NewReader("id: 5\n: comment\nretry: 100\ndata: x\n\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || string(events[0].Data) != "x" {
		t.Fatalf("ignored lines mishandled: %+v", events)
	}
}

func TestRelaySSETrailingEventFlushed(t *testing.T) {
	t.Parallel()
	// No terminating blank line before EOF.
	events, err := collectSSE(t, context.Background(), strings.NewReader("data: x"))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || string(events[0].Data) != "x" {
		t.Fatalf("trailing event not flushed at EOF: %+v", events)
	}
}

func TestRelaySSEEmptyEventDropped(t *testing.T) {
	t.Parallel()
	// A blank line with empty dataBuf yields no event.
	events, err := collectSSE(t, context.Background(), strings.NewReader("\n: only comment\n\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("expected no events, got %+v", events)
	}
}

func TestRelaySSEHandlerError(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("handler boom")
	err := relaySSE(context.Background(), strings.NewReader("data: x\n\n"),
		func(mcpproxy.SSEEvent) error { return sentinel }, testMaxEvent)
	if !errors.Is(err, sentinel) {
		t.Fatalf("handler error not propagated: %v", err)
	}
}

func TestRelaySSECtxCanceled(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := relaySSE(ctx, strings.NewReader("data: a\ndata: b\ndata: c\n\n"),
		func(mcpproxy.SSEEvent) error { return nil }, testMaxEvent)
	if err == nil || !strings.Contains(err.Error(), "legacy SSE canceled") {
		t.Fatalf("expected canceled error, got %v", err)
	}
}

// errReader returns some bytes then a non-EOF error.
type errReader struct {
	data []byte
	done bool
}

func (r *errReader) Read(p []byte) (int, error) {
	if !r.done {
		r.done = true
		n := copy(p, r.data)
		return n, nil
	}
	return 0, errors.New("read failure")
}

func TestRelaySSEScannerError(t *testing.T) {
	t.Parallel()
	// No newline so the scanner keeps reading and hits the error.
	err := relaySSE(context.Background(), &errReader{data: []byte("data: partial")},
		func(mcpproxy.SSEEvent) error { return nil }, testMaxEvent)
	if err == nil || !strings.Contains(err.Error(), "read legacy SSE") {
		t.Fatalf("expected scanner read error, got %v", err)
	}
}

func TestRelaySSEDataLeadingSpaceTrim(t *testing.T) {
	t.Parallel()
	withSpace, err := collectSSE(t, context.Background(), strings.NewReader("data: x\n\n"))
	if err != nil {
		t.Fatal(err)
	}
	noSpace, err := collectSSE(t, context.Background(), strings.NewReader("data:x\n\n"))
	if err != nil {
		t.Fatal(err)
	}
	if string(withSpace[0].Data) != "x" || string(noSpace[0].Data) != "x" {
		t.Fatalf("leading-space trim mismatch: %q vs %q", withSpace[0].Data, noSpace[0].Data)
	}
}
