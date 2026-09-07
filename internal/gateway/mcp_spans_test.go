package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// recordingRequest returns a request whose context carries a live, recording
// span so the annotate* helpers take their non-early-return path.
func recordingRequest(t *testing.T) (*http.Request, func()) {
	t.Helper()
	tp := sdktrace.NewTracerProvider()
	ctx, span := tp.Tracer("test").Start(context.Background(), "op")
	r := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody).WithContext(ctx)
	return r, func() {
		span.End()
		_ = tp.Shutdown(context.Background())
	}
}

func TestAnnotateRequestSpan_Recording(t *testing.T) {
	t.Parallel()

	r, done := recordingRequest(t)
	defer done()

	assert.True(t, trace.SpanFromContext(r.Context()).IsRecording())
	// name empty and non-empty branches.
	annotateRequestSpan(r, "tools/call", "", "2026-07-28")
	annotateRequestSpan(r, "tools/call", "weather", "2026-07-28")
}

func TestAnnotateOutcomeSpan_Recording(t *testing.T) {
	t.Parallel()

	r, done := recordingRequest(t)
	defer done()

	annotateOutcomeSpan(r, "up1", "complete", "success")
	// empty attributes are skipped.
	annotateOutcomeSpan(r, "", "", "")
}

func TestAnnotateOperationSpan_Recording(t *testing.T) {
	t.Parallel()

	r, done := recordingRequest(t)
	defer done()

	// empty operationID is a no-op.
	annotateOperationSpan(r, "")
	annotateOperationSpan(r, "op-123")
}

func TestAnnotateSpans_NotRecording(t *testing.T) {
	t.Parallel()

	// A plain request has no recording span => the annotate helpers early
	// return without panicking.
	r := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)
	assert.NotPanics(t, func() {
		annotateRequestSpan(r, "m", "n", "v")
		annotateOutcomeSpan(r, "u", "rt", "oc")
		annotateOperationSpan(r, "op")
	})
}
