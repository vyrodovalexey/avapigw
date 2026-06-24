package aggregate

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingTracer captures span names and nesting for U-OBS-3.
type recordingTracer struct {
	mu      sync.Mutex
	started []string
	errors  []error
}

type recordingSpan struct {
	tracer *recordingTracer
	ended  bool
}

func (rt *recordingTracer) Start(ctx context.Context, name string) (context.Context, Span) {
	rt.mu.Lock()
	rt.started = append(rt.started, name)
	rt.mu.Unlock()
	return ctx, &recordingSpan{tracer: rt}
}

func (rs *recordingSpan) End() { rs.ended = true }
func (rs *recordingSpan) RecordError(err error) {
	rs.tracer.mu.Lock()
	rs.tracer.errors = append(rs.tracer.errors, err)
	rs.tracer.mu.Unlock()
}

func (rt *recordingTracer) names() []string {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	out := make([]string, len(rt.started))
	copy(out, rt.started)
	return out
}

// U-OBS-3: spans nested (fanout → per-target children).
func TestTracer_SpansNested(t *testing.T) {
	rt := &recordingTracer{}
	inv := newMockInvoker(func(_ context.Context, tg Target, _ *Request) (*Response, error) {
		return okResponse(tg.Name), nil
	})
	agg := NewAggregator(inv, WithTracer(rt))
	cfg := &Config{Targets: targets("a", "b"), FailMode: FailModeAll}

	_, err := agg.Fanout(context.Background(), cfg, &Request{})
	require.NoError(t, err)

	names := rt.names()
	assert.Contains(t, names, "aggregate.fanout")
	// One child span per target.
	targetSpans := 0
	for _, n := range names {
		if n == "aggregate.target" {
			targetSpans++
		}
	}
	assert.Equal(t, 2, targetSpans)
}

func TestTracer_RecordsErrorOnFailModeNotMet(t *testing.T) {
	rt := &recordingTracer{}
	inv := newMockInvoker(func(_ context.Context, _ Target, _ *Request) (*Response, error) {
		return nil, errors.New("down")
	})
	agg := NewAggregator(inv, WithTracer(rt))
	cfg := &Config{Targets: targets("a"), FailMode: FailModeAll}

	_, err := agg.Fanout(context.Background(), cfg, &Request{})
	require.Error(t, err)
	rt.mu.Lock()
	defer rt.mu.Unlock()
	assert.NotEmpty(t, rt.errors)
}

func TestNopTracer(t *testing.T) {
	tr := NopTracer()
	ctx, span := tr.Start(context.Background(), "x")
	assert.NotNil(t, ctx)
	assert.NotPanics(t, func() {
		span.RecordError(errors.New("y"))
		span.RecordError(nil)
		span.End()
	})
}

func TestNewTracer_Real(t *testing.T) {
	tr := NewTracer()
	require.NotNil(t, tr)
	ctx, span := tr.Start(context.Background(), "aggregate.fanout")
	assert.NotNil(t, ctx)
	assert.NotPanics(t, func() {
		span.RecordError(errors.New("z"))
		span.RecordError(nil)
		span.End()
	})
}
