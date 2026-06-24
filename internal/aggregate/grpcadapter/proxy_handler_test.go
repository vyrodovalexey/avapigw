package grpcadapter

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	grpcproxy "github.com/vyrodovalexey/avapigw/internal/grpc/proxy"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// fakeServerStream is a minimal grpc.ServerStream for unary/streaming detection
// tests. recvScript drives successive RecvMsg calls; sent captures SendMsg.
type fakeServerStream struct {
	ctx        context.Context
	recvScript []recvStep
	recvIdx    int
	sent       [][]byte
}

type recvStep struct {
	payload []byte
	err     error
}

func (s *fakeServerStream) SetHeader(metadata.MD) error  { return nil }
func (s *fakeServerStream) SendHeader(metadata.MD) error { return nil }
func (s *fakeServerStream) SetTrailer(metadata.MD)       {}
func (s *fakeServerStream) Context() context.Context     { return s.ctx }

func (s *fakeServerStream) SendMsg(m interface{}) error {
	frame, ok := m.(*grpcproxy.Frame)
	if !ok {
		return errors.New("unexpected message type")
	}
	s.sent = append(s.sent, frame.Payload())
	return nil
}

func (s *fakeServerStream) RecvMsg(m interface{}) error {
	if s.recvIdx >= len(s.recvScript) {
		return io.EOF
	}
	step := s.recvScript[s.recvIdx]
	s.recvIdx++
	if step.err != nil {
		return step.err
	}
	if frame, ok := m.(*grpcproxy.Frame); ok {
		frame.SetPayload(step.payload)
	}
	return nil
}

func streamCtx(method string) context.Context {
	return grpc.NewContextWithServerTransportStream(
		context.Background(),
		&fakeTransportStream{method: method},
	)
}

type fakeTransportStream struct{ method string }

func (f *fakeTransportStream) Method() string               { return f.method }
func (f *fakeTransportStream) SetHeader(metadata.MD) error  { return nil }
func (f *fakeTransportStream) SendHeader(metadata.MD) error { return nil }
func (f *fakeTransportStream) SetTrailer(metadata.MD) error { return nil }

// (b) A streaming method with aggregate enabled returns a clear Unimplemented
// status. The client sends a second message (client-streaming), which the
// unary aggregate handler must reject.
func TestProxyHandler_StreamingRejected_Unimplemented(t *testing.T) {
	t.Parallel()

	h := NewProxyHandler(observability.NopLogger())
	stream := &fakeServerStream{
		ctx: streamCtx("/agg.Service/StreamMethod"),
		recvScript: []recvStep{
			{payload: []byte(`{"a":1}`)}, // first request message
			{payload: []byte(`{"b":2}`)}, // second message => client streaming
		},
	}

	err := h.HandleAggregate(nil, stream, cfgWith(false, "a", "b"), newTestPool(t))
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unimplemented, st.Code())
	assert.Contains(t, st.Message(), "streaming aggregate not supported")
	assert.Empty(t, stream.sent, "no response must be sent for a rejected streaming call")
}

// An empty request stream (immediate EOF) is rejected with InvalidArgument.
func TestProxyHandler_EmptyStream_InvalidArgument(t *testing.T) {
	t.Parallel()

	h := NewProxyHandler(observability.NopLogger())
	stream := &fakeServerStream{
		ctx: streamCtx("/agg.Service/Method"),
		recvScript: []recvStep{
			{err: io.EOF},
		},
	}

	err := h.HandleAggregate(nil, stream, cfgWith(false, "a"), newTestPool(t))
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

// A missing method in context yields Internal.
func TestProxyHandler_NoMethod_Internal(t *testing.T) {
	t.Parallel()

	h := NewProxyHandler(observability.NopLogger())
	stream := &fakeServerStream{ctx: context.Background()}

	err := h.HandleAggregate(nil, stream, cfgWith(false, "a"), newTestPool(t))
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
}

func TestNewProxyHandler_Defaults(t *testing.T) {
	t.Parallel()

	h := NewProxyHandler(nil)
	require.NotNil(t, h)
	assert.NotNil(t, h.logger)
	assert.NotNil(t, h.metrics)
	assert.NotNil(t, h.tracer)
}

// newTestPool returns a real (empty) connection pool for handler tests that do
// not reach the dialing path.
func newTestPool(t *testing.T) *grpcproxy.ConnectionPool {
	t.Helper()
	pool := grpcproxy.NewConnectionPool(grpcproxy.WithPoolLogger(observability.NopLogger()))
	t.Cleanup(func() { _ = pool.Close() })
	return pool
}
