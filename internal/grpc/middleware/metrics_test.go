package middleware

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestNewGRPCMetrics(t *testing.T) {
	t.Parallel()

	registry := prometheus.NewRegistry()
	metrics := NewGRPCMetrics("test", registry)

	assert.NotNil(t, metrics)
	assert.NotNil(t, metrics.requestsTotal)
	assert.NotNil(t, metrics.requestDuration)
	assert.NotNil(t, metrics.streamMsgsSent)
	assert.NotNil(t, metrics.streamMsgsReceived)
	assert.NotNil(t, metrics.activeStreams)
}

func TestNewGRPCMetrics_DefaultNamespace(t *testing.T) {
	t.Parallel()

	registry := prometheus.NewRegistry()
	metrics := NewGRPCMetrics("", registry)

	assert.NotNil(t, metrics)
}

func TestGRPCMetrics_RecordRequest(t *testing.T) {
	t.Parallel()

	registry := prometheus.NewRegistry()
	metrics := NewGRPCMetrics("test", registry)

	// Should not panic
	metrics.RecordRequest("test.Service", "GetUser", codes.OK, 100*time.Millisecond)
	metrics.RecordRequest("test.Service", "GetUser", codes.Internal, 200*time.Millisecond)
}

func TestGRPCMetrics_RecordStreamMsgSent(t *testing.T) {
	t.Parallel()

	registry := prometheus.NewRegistry()
	metrics := NewGRPCMetrics("test", registry)

	// Should not panic
	metrics.RecordStreamMsgSent("test.Service", "StreamMethod")
	metrics.RecordStreamMsgSent("test.Service", "StreamMethod")
}

func TestGRPCMetrics_RecordStreamMsgReceived(t *testing.T) {
	t.Parallel()

	registry := prometheus.NewRegistry()
	metrics := NewGRPCMetrics("test", registry)

	// Should not panic
	metrics.RecordStreamMsgReceived("test.Service", "StreamMethod")
	metrics.RecordStreamMsgReceived("test.Service", "StreamMethod")
}

func TestGRPCMetrics_ActiveStreams(t *testing.T) {
	t.Parallel()

	registry := prometheus.NewRegistry()
	metrics := NewGRPCMetrics("test", registry)

	// Should not panic
	metrics.IncrementActiveStreams("test.Service", "StreamMethod")
	metrics.IncrementActiveStreams("test.Service", "StreamMethod")
	metrics.DecrementActiveStreams("test.Service", "StreamMethod")
}

func TestUnaryMetricsInterceptor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		handlerErr  error
		expectedErr bool
	}{
		{
			name:        "successful request",
			handlerErr:  nil,
			expectedErr: false,
		},
		{
			name:        "failed request",
			handlerErr:  status.Error(codes.Internal, "internal error"),
			expectedErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			registry := prometheus.NewRegistry()
			metrics := NewGRPCMetrics("test", registry)
			interceptor := UnaryMetricsInterceptor(metrics)

			ctx := context.Background()
			info := &grpc.UnaryServerInfo{
				FullMethod: "/test.Service/Method",
			}

			handler := func(ctx context.Context, req interface{}) (interface{}, error) {
				return "response", tt.handlerErr
			}

			resp, err := interceptor(ctx, "request", info, handler)

			if tt.expectedErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, "response", resp)
			}
		})
	}
}

func TestStreamMetricsInterceptor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		handlerErr  error
		expectedErr bool
	}{
		{
			name:        "successful stream",
			handlerErr:  nil,
			expectedErr: false,
		},
		{
			name:        "failed stream",
			handlerErr:  status.Error(codes.Internal, "internal error"),
			expectedErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			registry := prometheus.NewRegistry()
			metrics := NewGRPCMetrics("test", registry)
			interceptor := StreamMetricsInterceptor(metrics)

			ctx := context.Background()
			stream := &metricsTestServerStream{ctx: ctx}
			info := &grpc.StreamServerInfo{
				FullMethod: "/test.Service/StreamMethod",
			}

			handler := func(srv interface{}, stream grpc.ServerStream) error {
				return tt.handlerErr
			}

			err := interceptor(nil, stream, info, handler)

			if tt.expectedErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMetricsServerStream_SendMsg(t *testing.T) {
	t.Parallel()

	registry := prometheus.NewRegistry()
	metrics := NewGRPCMetrics("test", registry)

	inner := &metricsTestServerStream{ctx: context.Background()}
	stream := &metricsServerStream{
		ServerStream: inner,
		metrics:      metrics,
		service:      "test.Service",
		method:       "StreamMethod",
	}

	err := stream.SendMsg("message")
	assert.NoError(t, err)
}

func TestMetricsServerStream_SendMsg_Error(t *testing.T) {
	t.Parallel()

	registry := prometheus.NewRegistry()
	metrics := NewGRPCMetrics("test", registry)

	inner := &metricsTestServerStream{
		ctx:     context.Background(),
		sendErr: status.Error(codes.Internal, "send error"),
	}
	stream := &metricsServerStream{
		ServerStream: inner,
		metrics:      metrics,
		service:      "test.Service",
		method:       "StreamMethod",
	}

	err := stream.SendMsg("message")
	assert.Error(t, err)
}

func TestMetricsServerStream_RecvMsg(t *testing.T) {
	t.Parallel()

	registry := prometheus.NewRegistry()
	metrics := NewGRPCMetrics("test", registry)

	inner := &metricsTestServerStream{ctx: context.Background()}
	stream := &metricsServerStream{
		ServerStream: inner,
		metrics:      metrics,
		service:      "test.Service",
		method:       "StreamMethod",
	}

	err := stream.RecvMsg(nil)
	assert.NoError(t, err)
}

func TestMetricsServerStream_RecvMsg_Error(t *testing.T) {
	t.Parallel()

	registry := prometheus.NewRegistry()
	metrics := NewGRPCMetrics("test", registry)

	inner := &metricsTestServerStream{
		ctx:     context.Background(),
		recvErr: status.Error(codes.Internal, "recv error"),
	}
	stream := &metricsServerStream{
		ServerStream: inner,
		metrics:      metrics,
		service:      "test.Service",
		method:       "StreamMethod",
	}

	err := stream.RecvMsg(nil)
	assert.Error(t, err)
}

// metricsTestServerStream implements grpc.ServerStream for testing
type metricsTestServerStream struct {
	ctx     context.Context
	sendErr error
	recvErr error
}

func (m *metricsTestServerStream) SetHeader(_ metadata.MD) error  { return nil }
func (m *metricsTestServerStream) SendHeader(_ metadata.MD) error { return nil }
func (m *metricsTestServerStream) SetTrailer(_ metadata.MD)       {}
func (m *metricsTestServerStream) Context() context.Context       { return m.ctx }
func (m *metricsTestServerStream) SendMsg(_ interface{}) error    { return m.sendErr }
func (m *metricsTestServerStream) RecvMsg(_ interface{}) error    { return m.recvErr }

func TestStreamMetricsInterceptor_ActiveStreamsTracking(t *testing.T) {
	t.Parallel()

	registry := prometheus.NewRegistry()
	metrics := NewGRPCMetrics("test", registry)
	interceptor := StreamMetricsInterceptor(metrics)

	ctx := context.Background()
	stream := &metricsTestServerStream{ctx: ctx}
	info := &grpc.StreamServerInfo{
		FullMethod: "/test.Service/StreamMethod",
	}

	handler := func(srv interface{}, stream grpc.ServerStream) error {
		// Active streams should be incremented here
		return nil
	}

	err := interceptor(nil, stream, info, handler)
	require.NoError(t, err)
	// Active streams should be decremented after handler returns
}
