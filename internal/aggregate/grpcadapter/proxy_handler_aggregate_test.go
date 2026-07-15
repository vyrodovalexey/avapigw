package grpcadapter

// WP15 — coverage for the gRPC aggregate ProxyHandler: full HandleAggregate
// fan-out over the real connection pool against an in-process echo backend,
// aggregate-error/send-error propagation, incoming-header extraction,
// aggregate-status mapping, and option application.

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/vyrodovalexey/avapigw/internal/aggregate"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// fakeTracer is a distinguishable aggregate.Tracer for option-identity tests.
type fakeTracer struct{ aggregate.Tracer }

// ----------------------------------------------------------------------------
// Options / constructor.
// ----------------------------------------------------------------------------

// HAPPY: WithProxyHandlerMetrics installs the recorder; EDGE: nil is ignored.
func TestWithProxyHandlerMetrics(t *testing.T) {
	t.Parallel()

	m := aggregate.NopMetrics()
	h := &ProxyHandler{}

	WithProxyHandlerMetrics(m)(h)
	assert.Same(t, m, h.metrics, "option must install the provided metrics")

	WithProxyHandlerMetrics(nil)(h)
	assert.Same(t, m, h.metrics, "nil metrics must not replace the current recorder")
}

// HAPPY: WithProxyHandlerTracer installs the tracer; EDGE: nil is ignored.
func TestWithProxyHandlerTracer(t *testing.T) {
	t.Parallel()

	tr := &fakeTracer{Tracer: aggregate.NopTracer()}
	h := &ProxyHandler{}

	WithProxyHandlerTracer(tr)(h)
	assert.Same(t, tr, h.tracer, "option must install the provided tracer")

	WithProxyHandlerTracer(nil)(h)
	assert.Same(t, tr, h.tracer, "nil tracer must not replace the current tracer")
}

// HAPPY: NewProxyHandler applies logger and options.
func TestNewProxyHandler_WithOptions(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	m := aggregate.NopMetrics()
	tr := &fakeTracer{Tracer: aggregate.NopTracer()}

	h := NewProxyHandler(logger,
		WithProxyHandlerMetrics(m),
		WithProxyHandlerTracer(tr),
	)

	require.NotNil(t, h)
	assert.Same(t, logger, h.logger)
	assert.Same(t, m, h.metrics)
	assert.Same(t, tr, h.tracer)
}

// ----------------------------------------------------------------------------
// incomingHeaders.
// ----------------------------------------------------------------------------

// EDGE: incomingHeaders returns nil without metadata, drops pseudo/empty keys,
// and deep-copies values.
func TestIncomingHeaders(t *testing.T) {
	t.Parallel()

	t.Run("no metadata returns nil", func(t *testing.T) {
		t.Parallel()

		assert.Nil(t, incomingHeaders(context.Background()))
	})

	t.Run("empty metadata returns empty map", func(t *testing.T) {
		t.Parallel()

		ctx := metadata.NewIncomingContext(context.Background(), metadata.MD{})

		out := incomingHeaders(ctx)

		require.NotNil(t, out)
		assert.Empty(t, out)
	})

	t.Run("drops pseudo-headers and empty keys", func(t *testing.T) {
		t.Parallel()

		md := metadata.MD{
			":authority": {"gw.example.com"},
			"":           {"must-be-dropped"},
			"x-tenant":   {"acme", "beta"},
			"x-trace-id": {"t-1"},
		}
		ctx := metadata.NewIncomingContext(context.Background(), md)

		out := incomingHeaders(ctx)

		assert.Equal(t, map[string][]string{
			"x-tenant":   {"acme", "beta"},
			"x-trace-id": {"t-1"},
		}, out)
	})

	t.Run("values are copied, not aliased", func(t *testing.T) {
		t.Parallel()

		md := metadata.MD{"x-key": {"original"}}
		ctx := metadata.NewIncomingContext(context.Background(), md)

		out := incomingHeaders(ctx)

		md["x-key"][0] = "mutated"
		assert.Equal(t, []string{"original"}, out["x-key"],
			"forwarded headers must not alias the inbound metadata slices")
	})
}

// ----------------------------------------------------------------------------
// aggregateStatus.
// ----------------------------------------------------------------------------

// HAPPY/ERROR: aggregateStatus maps engine outcomes onto gRPC codes.
func TestAggregateStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      error
		wantCode codes.Code
		wantMsg  string
	}{
		{
			name: "nil maps to OK",
			err:  nil,
		},
		{
			name:     "ErrNoTargets maps to FailedPrecondition",
			err:      aggregate.ErrNoTargets,
			wantCode: codes.FailedPrecondition,
			wantMsg:  "no targets configured",
		},
		{
			name:     "wrapped ErrNoTargets still detected",
			err:      fmt.Errorf("aggregate handler: %w", aggregate.ErrNoTargets),
			wantCode: codes.FailedPrecondition,
			wantMsg:  "no targets configured",
		},
		{
			name:     "fail-mode threshold error maps to Unavailable",
			err:      aggregate.ErrFailModeNotMet,
			wantCode: codes.Unavailable,
			wantMsg:  "aggregate fan-out failed",
		},
		{
			name:     "generic error maps to Unavailable with cause",
			err:      errors.New("kaboom"),
			wantCode: codes.Unavailable,
			wantMsg:  "aggregate fan-out failed: kaboom",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := aggregateStatus(tt.err)

			if tt.err == nil {
				assert.NoError(t, got)
				return
			}
			require.Error(t, got)
			st, ok := status.FromError(got)
			require.True(t, ok)
			assert.Equal(t, tt.wantCode, st.Code())
			assert.Contains(t, st.Message(), tt.wantMsg)
		})
	}
}

// ----------------------------------------------------------------------------
// receiveUnaryRequest.
// ----------------------------------------------------------------------------

// ERROR: a non-EOF receive failure is returned verbatim (no status rewrite).
func TestReceiveUnaryRequest_RecvErrorPassthrough(t *testing.T) {
	t.Parallel()

	recvErr := status.Error(codes.Canceled, "client went away")
	stream := &fakeServerStream{
		ctx:        streamCtx("/agg.Service/Method"),
		recvScript: []recvStep{{err: recvErr}},
	}

	body, err := receiveUnaryRequest(stream, "/agg.Service/Method", observability.NopLogger())

	require.Error(t, err)
	assert.Equal(t, codes.Canceled, status.Code(err))
	assert.Nil(t, body)
}

// ----------------------------------------------------------------------------
// HandleAggregate — full fan-out over the real connection pool.
// ----------------------------------------------------------------------------

// aggregateCfg builds an enabled aggregate config whose targets all point at
// the given echo backend.
func aggregateCfg(backend *echoBackend, failMode config.FailMode, names ...string) *config.AggregateConfig {
	targets := make([]config.AggregateTarget, 0, len(names))
	for _, name := range names {
		targets = append(targets, config.AggregateTarget{
			Name:        name,
			Destination: config.Destination{Host: backend.host, Port: backend.port},
		})
	}
	return &config.AggregateConfig{Enabled: true, FailMode: failMode, Targets: targets}
}

// sendFailStream wraps fakeServerStream with an injected SendMsg failure.
type sendFailStream struct {
	*fakeServerStream
	sendErr error
}

func (s *sendFailStream) SendMsg(interface{}) error { return s.sendErr }

// HAPPY: a unary aggregate call fans out to every target through the real
// connection pool, forwards inbound metadata, and sends exactly one merged
// (labeled-envelope) response.
func TestHandleAggregate_HappyPath_FanoutOverRealPool(t *testing.T) {
	t.Parallel()

	backend := startTCPEcho(t, nil, echoBehavior{respBody: []byte(`{"greeting":"hello"}`)})
	pool := newTestPool(t)
	h := NewProxyHandler(observability.NopLogger())

	inMD := metadata.Pairs("x-tenant", "acme")
	ctx := metadata.NewIncomingContext(streamCtx("/agg.Service/Get"), inMD)
	stream := &fakeServerStream{
		ctx:        ctx,
		recvScript: []recvStep{{payload: []byte(`{"q":1}`)}},
	}

	err := h.HandleAggregate(nil, stream, aggregateCfg(backend, config.FailModeAll, "alpha", "beta"), pool)

	require.NoError(t, err)
	require.Len(t, stream.sent, 1, "exactly one aggregated response must be sent")
	payload := string(stream.sent[0])
	assert.Contains(t, payload, "alpha")
	assert.Contains(t, payload, "beta")

	calls := backend.capturedCalls()
	require.Len(t, calls, 2, "both targets must be invoked")
	for _, call := range calls {
		assert.Equal(t, "/agg.Service/Get", call.method,
			"the inbound full method must be re-invoked on every target")
		assert.Equal(t, []byte(`{"q":1}`), call.body)
		assert.Equal(t, []string{"acme"}, call.md.Get("x-tenant"),
			"inbound metadata must be forwarded to the fan-out targets")
	}
}

// ERROR: a disabled/empty aggregate config yields ErrNoTargets mapped to
// FailedPrecondition; nothing is sent on the stream.
func TestHandleAggregate_NoTargets_FailedPrecondition(t *testing.T) {
	t.Parallel()

	h := NewProxyHandler(observability.NopLogger())
	stream := &fakeServerStream{
		ctx:        streamCtx("/agg.Service/Get"),
		recvScript: []recvStep{{payload: []byte(`{"q":1}`)}},
	}

	err := h.HandleAggregate(nil, stream, &config.AggregateConfig{Enabled: false}, newTestPool(t))

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
	assert.Empty(t, stream.sent)
}

// ERROR: when every target fails, the fail-mode error surfaces as Unavailable
// and no response message is sent.
func TestHandleAggregate_BackendFailure_Unavailable(t *testing.T) {
	t.Parallel()

	backend := startTCPEcho(t, nil, echoBehavior{
		respErr: status.Error(codes.Internal, "backend boom"),
	})
	h := NewProxyHandler(observability.NopLogger())
	stream := &fakeServerStream{
		ctx:        streamCtx("/agg.Service/Get"),
		recvScript: []recvStep{{payload: []byte(`{"q":1}`)}},
	}

	cfg := aggregateCfg(backend, config.FailModeAll, "only")
	// Bound the per-target retry loop so the failing fan-out stays fast.
	cfg.Targets[0].Timeout = config.Duration(2 * time.Second)

	err := h.HandleAggregate(nil, stream, cfg, newTestPool(t))

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unavailable, st.Code())
	assert.Contains(t, st.Message(), "aggregate fan-out failed")
	assert.Empty(t, stream.sent)
}

// ERROR: a failure to send the aggregated response propagates the send error.
func TestHandleAggregate_SendError(t *testing.T) {
	t.Parallel()

	backend := startTCPEcho(t, nil, echoBehavior{respBody: []byte(`{"ok":true}`)})
	h := NewProxyHandler(observability.NopLogger())

	sendErr := errors.New("stream torn down")
	stream := &sendFailStream{
		fakeServerStream: &fakeServerStream{
			ctx:        streamCtx("/agg.Service/Get"),
			recvScript: []recvStep{{payload: []byte(`{"q":1}`)}},
		},
		sendErr: sendErr,
	}

	err := h.HandleAggregate(nil, stream, aggregateCfg(backend, config.FailModeAll, "alpha"), newTestPool(t))

	require.Error(t, err)
	assert.ErrorIs(t, err, sendErr)
	require.Len(t, backend.capturedCalls(), 1, "the fan-out itself must have succeeded")
}
