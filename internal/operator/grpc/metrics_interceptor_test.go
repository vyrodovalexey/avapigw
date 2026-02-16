// Package grpc provides unit tests for gRPC server metrics interceptors.
package grpc

import (
	"context"
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// newTestGRPCServerMetrics creates a grpcServerMetrics instance with a fresh registry
// to avoid duplicate registration panics across tests.
func newTestGRPCServerMetrics(t *testing.T) *grpcServerMetrics {
	t.Helper()
	reg := prometheus.NewRegistry()
	return newGRPCServerMetricsWithFactory(promauto.With(reg))
}

// ============================================================================
// grpcServerMetrics Construction Tests
// ============================================================================

func TestNewGRPCServerMetricsWithFactory(t *testing.T) {
	m := newTestGRPCServerMetrics(t)

	assert.NotNil(t, m.requestsTotal, "requestsTotal should not be nil")
	assert.NotNil(t, m.requestDuration, "requestDuration should not be nil")
	assert.NotNil(t, m.activeStreams, "activeStreams should not be nil")
	assert.NotNil(t, m.streamMsgSent, "streamMsgSent should not be nil")
	assert.NotNil(t, m.streamMsgReceived, "streamMsgReceived should not be nil")
}

func TestGetGRPCServerMetrics_Singleton(t *testing.T) {
	// getGRPCServerMetrics uses sync.Once, so calling it multiple times returns the same instance.
	m1 := getGRPCServerMetrics()
	m2 := getGRPCServerMetrics()
	assert.Same(t, m1, m2, "getGRPCServerMetrics should return the same singleton instance")
}

// ============================================================================
// Unary Server Interceptor Tests
// ============================================================================

func TestUnaryServerInterceptor_Success(t *testing.T) {
	m := newTestGRPCServerMetrics(t)
	interceptor := m.UnaryServerInterceptor()

	handler := func(_ context.Context, _ interface{}) (interface{}, error) {
		return "response", nil
	}

	info := &grpc.UnaryServerInfo{
		FullMethod: "/operator.v1alpha1.ConfigurationService/RegisterGateway",
	}

	resp, err := interceptor(context.Background(), "request", info, handler)

	assert.NoError(t, err)
	assert.Equal(t, "response", resp)
}

func TestUnaryServerInterceptor_Error(t *testing.T) {
	m := newTestGRPCServerMetrics(t)
	interceptor := m.UnaryServerInterceptor()

	handler := func(_ context.Context, _ interface{}) (interface{}, error) {
		return nil, status.Error(codes.InvalidArgument, "bad request")
	}

	info := &grpc.UnaryServerInfo{
		FullMethod: "/operator.v1alpha1.ConfigurationService/RegisterGateway",
	}

	resp, err := interceptor(context.Background(), "request", info, handler)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestUnaryServerInterceptor_InternalError(t *testing.T) {
	m := newTestGRPCServerMetrics(t)
	interceptor := m.UnaryServerInterceptor()

	handler := func(_ context.Context, _ interface{}) (interface{}, error) {
		return nil, status.Error(codes.Internal, "internal error")
	}

	info := &grpc.UnaryServerInfo{
		FullMethod: "/operator.v1alpha1.ConfigurationService/GetConfiguration",
	}

	resp, err := interceptor(context.Background(), "request", info, handler)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestUnaryServerInterceptor_MultipleMethods(t *testing.T) {
	m := newTestGRPCServerMetrics(t)
	interceptor := m.UnaryServerInterceptor()

	methods := []string{
		"/operator.v1alpha1.ConfigurationService/RegisterGateway",
		"/operator.v1alpha1.ConfigurationService/GetConfiguration",
		"/operator.v1alpha1.ConfigurationService/Heartbeat",
		"/operator.v1alpha1.ConfigurationService/AcknowledgeConfiguration",
	}

	for _, method := range methods {
		info := &grpc.UnaryServerInfo{FullMethod: method}
		handler := func(_ context.Context, _ interface{}) (interface{}, error) {
			return "ok", nil
		}

		resp, err := interceptor(context.Background(), "request", info, handler)
		assert.NoError(t, err)
		assert.Equal(t, "ok", resp)
	}
}

// ============================================================================
// Stream Server Interceptor Tests
// ============================================================================

// metricsTestStream implements grpc.ServerStream for metrics interceptor testing.
type metricsTestStream struct {
	grpc.ServerStream
	ctx        context.Context
	sendErr    error
	recvErr    error
	sendCalled int
	recvCalled int
}

func (m *metricsTestStream) Context() context.Context {
	return m.ctx
}

func (m *metricsTestStream) SendMsg(_ interface{}) error {
	m.sendCalled++
	return m.sendErr
}

func (m *metricsTestStream) RecvMsg(_ interface{}) error {
	m.recvCalled++
	return m.recvErr
}

func TestStreamServerInterceptor_Success(t *testing.T) {
	m := newTestGRPCServerMetrics(t)
	interceptor := m.StreamServerInterceptor()

	stream := &metricsTestStream{ctx: context.Background()}
	info := &grpc.StreamServerInfo{
		FullMethod:     "/operator.v1alpha1.ConfigurationService/StreamConfiguration",
		IsServerStream: true,
	}

	handler := func(_ interface{}, _ grpc.ServerStream) error {
		return nil
	}

	err := interceptor(nil, stream, info, handler)
	assert.NoError(t, err)
}

func TestStreamServerInterceptor_Error(t *testing.T) {
	m := newTestGRPCServerMetrics(t)
	interceptor := m.StreamServerInterceptor()

	stream := &metricsTestStream{ctx: context.Background()}
	info := &grpc.StreamServerInfo{
		FullMethod:     "/operator.v1alpha1.ConfigurationService/StreamConfiguration",
		IsServerStream: true,
	}

	handler := func(_ interface{}, _ grpc.ServerStream) error {
		return status.Error(codes.Unavailable, "service unavailable")
	}

	err := interceptor(nil, stream, info, handler)
	assert.Error(t, err)
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

func TestStreamServerInterceptor_WithMessageCounting(t *testing.T) {
	m := newTestGRPCServerMetrics(t)
	interceptor := m.StreamServerInterceptor()

	stream := &metricsTestStream{ctx: context.Background()}
	info := &grpc.StreamServerInfo{
		FullMethod:     "/operator.v1alpha1.ConfigurationService/StreamConfiguration",
		IsServerStream: true,
	}

	handler := func(_ interface{}, ss grpc.ServerStream) error {
		// Send some messages
		for i := 0; i < 3; i++ {
			if err := ss.SendMsg("msg"); err != nil {
				return err
			}
		}
		// Receive some messages
		for i := 0; i < 2; i++ {
			if err := ss.RecvMsg(nil); err != nil {
				return err
			}
		}
		return nil
	}

	err := interceptor(nil, stream, info, handler)
	assert.NoError(t, err)
	assert.Equal(t, 3, stream.sendCalled)
	assert.Equal(t, 2, stream.recvCalled)
}

// ============================================================================
// wrappedServerStream Tests
// ============================================================================

func TestWrappedServerStream_SendMsg_Success(t *testing.T) {
	m := newTestGRPCServerMetrics(t)
	stream := &metricsTestStream{ctx: context.Background()}

	wrapped := &wrappedServerStream{
		ServerStream: stream,
		method:       "/test/Method",
		metrics:      m,
	}

	err := wrapped.SendMsg("test")
	assert.NoError(t, err)
	assert.Equal(t, 1, stream.sendCalled)
}

func TestWrappedServerStream_SendMsg_Error(t *testing.T) {
	m := newTestGRPCServerMetrics(t)
	sendErr := errors.New("send failed")
	stream := &metricsTestStream{ctx: context.Background(), sendErr: sendErr}

	wrapped := &wrappedServerStream{
		ServerStream: stream,
		method:       "/test/Method",
		metrics:      m,
	}

	err := wrapped.SendMsg("test")
	assert.Error(t, err)
	assert.Equal(t, sendErr, err)
	assert.Equal(t, 1, stream.sendCalled)
}

func TestWrappedServerStream_RecvMsg_Success(t *testing.T) {
	m := newTestGRPCServerMetrics(t)
	stream := &metricsTestStream{ctx: context.Background()}

	wrapped := &wrappedServerStream{
		ServerStream: stream,
		method:       "/test/Method",
		metrics:      m,
	}

	err := wrapped.RecvMsg(nil)
	assert.NoError(t, err)
	assert.Equal(t, 1, stream.recvCalled)
}

func TestWrappedServerStream_RecvMsg_Error(t *testing.T) {
	m := newTestGRPCServerMetrics(t)
	recvErr := errors.New("recv failed")
	stream := &metricsTestStream{ctx: context.Background(), recvErr: recvErr}

	wrapped := &wrappedServerStream{
		ServerStream: stream,
		method:       "/test/Method",
		metrics:      m,
	}

	err := wrapped.RecvMsg(nil)
	assert.Error(t, err)
	assert.Equal(t, recvErr, err)
	assert.Equal(t, 1, stream.recvCalled)
}

func TestWrappedServerStream_MultipleSendRecv(t *testing.T) {
	m := newTestGRPCServerMetrics(t)
	stream := &metricsTestStream{ctx: context.Background()}

	wrapped := &wrappedServerStream{
		ServerStream: stream,
		method:       "/test/Method",
		metrics:      m,
	}

	// Send 5 messages
	for i := 0; i < 5; i++ {
		err := wrapped.SendMsg("msg")
		require.NoError(t, err)
	}

	// Receive 3 messages
	for i := 0; i < 3; i++ {
		err := wrapped.RecvMsg(nil)
		require.NoError(t, err)
	}

	assert.Equal(t, 5, stream.sendCalled)
	assert.Equal(t, 3, stream.recvCalled)
}

// ============================================================================
// Metrics Registration Tests
// ============================================================================

func TestGRPCServerMetrics_MetricNames(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newGRPCServerMetricsWithFactory(promauto.With(reg))

	// Initialize metrics with label values so they appear in Gather()
	m.requestsTotal.WithLabelValues("/test/Method", "OK").Inc()
	m.requestDuration.WithLabelValues("/test/Method").Observe(0.01)
	m.activeStreams.Set(0)
	m.streamMsgSent.WithLabelValues("/test/Method").Inc()
	m.streamMsgReceived.WithLabelValues("/test/Method").Inc()

	// Gather all metrics from the registry
	families, err := reg.Gather()
	require.NoError(t, err)

	expectedNames := map[string]bool{
		"avapigw_operator_grpc_server_requests_total":                 false,
		"avapigw_operator_grpc_server_request_duration_seconds":       false,
		"avapigw_operator_grpc_server_active_streams":                 false,
		"avapigw_operator_grpc_server_stream_messages_sent_total":     false,
		"avapigw_operator_grpc_server_stream_messages_received_total": false,
	}

	for _, family := range families {
		if _, ok := expectedNames[family.GetName()]; ok {
			expectedNames[family.GetName()] = true
		}
	}

	for name, found := range expectedNames {
		assert.True(t, found, "metric %s should be registered", name)
	}
}

// ============================================================================
// Integration-style Tests
// ============================================================================

func TestUnaryInterceptor_RecordsMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newGRPCServerMetricsWithFactory(promauto.With(reg))
	interceptor := m.UnaryServerInterceptor()

	info := &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/Method",
	}

	// Successful call
	handler := func(_ context.Context, _ interface{}) (interface{}, error) {
		return "ok", nil
	}
	_, err := interceptor(context.Background(), nil, info, handler)
	require.NoError(t, err)

	// Failed call
	failHandler := func(_ context.Context, _ interface{}) (interface{}, error) {
		return nil, status.Error(codes.NotFound, "not found")
	}
	_, err = interceptor(context.Background(), nil, info, failHandler)
	require.Error(t, err)

	// Verify metrics were recorded
	families, err := reg.Gather()
	require.NoError(t, err)

	foundRequestsTotal := false
	foundDuration := false
	for _, family := range families {
		switch family.GetName() {
		case "avapigw_operator_grpc_server_requests_total":
			foundRequestsTotal = true
			// Should have 2 metric entries (OK and NotFound)
			assert.GreaterOrEqual(t, len(family.GetMetric()), 2)
		case "avapigw_operator_grpc_server_request_duration_seconds":
			foundDuration = true
			assert.NotEmpty(t, family.GetMetric())
		}
	}

	assert.True(t, foundRequestsTotal, "requests_total metric should be recorded")
	assert.True(t, foundDuration, "request_duration_seconds metric should be recorded")
}

func TestStreamInterceptor_RecordsMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newGRPCServerMetricsWithFactory(promauto.With(reg))
	interceptor := m.StreamServerInterceptor()

	stream := &metricsTestStream{ctx: context.Background()}
	info := &grpc.StreamServerInfo{
		FullMethod:     "/test.Service/StreamMethod",
		IsServerStream: true,
	}

	handler := func(_ interface{}, ss grpc.ServerStream) error {
		// Send and receive messages
		_ = ss.SendMsg("msg1")
		_ = ss.SendMsg("msg2")
		_ = ss.RecvMsg(nil)
		return nil
	}

	err := interceptor(nil, stream, info, handler)
	require.NoError(t, err)

	// Verify metrics were recorded
	families, err := reg.Gather()
	require.NoError(t, err)

	foundSent := false
	foundReceived := false
	foundActiveStreams := false
	for _, family := range families {
		switch family.GetName() {
		case "avapigw_operator_grpc_server_stream_messages_sent_total":
			foundSent = true
			assert.NotEmpty(t, family.GetMetric())
		case "avapigw_operator_grpc_server_stream_messages_received_total":
			foundReceived = true
			assert.NotEmpty(t, family.GetMetric())
		case "avapigw_operator_grpc_server_active_streams":
			foundActiveStreams = true
			// After handler completes, active streams should be back to 0
			assert.Equal(t, float64(0), family.GetMetric()[0].GetGauge().GetValue())
		}
	}

	assert.True(t, foundSent, "stream_messages_sent_total metric should be recorded")
	assert.True(t, foundReceived, "stream_messages_received_total metric should be recorded")
	assert.True(t, foundActiveStreams, "active_streams metric should be recorded")
}

// ============================================================================
// Table-Driven Tests for Status Codes
// ============================================================================

func TestUnaryInterceptor_StatusCodes(t *testing.T) {
	tests := []struct {
		name         string
		handlerErr   error
		expectedCode codes.Code
	}{
		{
			name:         "OK",
			handlerErr:   nil,
			expectedCode: codes.OK,
		},
		{
			name:         "InvalidArgument",
			handlerErr:   status.Error(codes.InvalidArgument, "invalid"),
			expectedCode: codes.InvalidArgument,
		},
		{
			name:         "NotFound",
			handlerErr:   status.Error(codes.NotFound, "not found"),
			expectedCode: codes.NotFound,
		},
		{
			name:         "Internal",
			handlerErr:   status.Error(codes.Internal, "internal"),
			expectedCode: codes.Internal,
		},
		{
			name:         "Unavailable",
			handlerErr:   status.Error(codes.Unavailable, "unavailable"),
			expectedCode: codes.Unavailable,
		},
		{
			name:         "PermissionDenied",
			handlerErr:   status.Error(codes.PermissionDenied, "denied"),
			expectedCode: codes.PermissionDenied,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newTestGRPCServerMetrics(t)
			interceptor := m.UnaryServerInterceptor()

			info := &grpc.UnaryServerInfo{
				FullMethod: "/test.Service/Method",
			}

			handler := func(_ context.Context, _ interface{}) (interface{}, error) {
				if tt.handlerErr != nil {
					return nil, tt.handlerErr
				}
				return "ok", nil
			}

			resp, err := interceptor(context.Background(), nil, info, handler)

			if tt.handlerErr != nil {
				assert.Error(t, err)
				assert.Nil(t, resp)
				assert.Equal(t, tt.expectedCode, status.Code(err))
			} else {
				assert.NoError(t, err)
				assert.Equal(t, "ok", resp)
			}
		})
	}
}
