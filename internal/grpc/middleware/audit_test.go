package middleware

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/vyrodovalexey/avapigw/internal/audit"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// mockAuditLogger captures audit events for testing.
type mockAuditLogger struct {
	events []*audit.Event
	mu     sync.Mutex
}

func (m *mockAuditLogger) LogEvent(_ context.Context, event *audit.Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, event)
}

func (m *mockAuditLogger) LogAuthentication(_ context.Context, _ audit.Action, _ audit.Outcome, _ *audit.Subject) {
}

func (m *mockAuditLogger) LogAuthorization(_ context.Context, _ audit.Outcome, _ *audit.Subject, _ *audit.Resource) {
}

func (m *mockAuditLogger) LogSecurity(_ context.Context, _ audit.Action, _ audit.Outcome, _ *audit.Subject, _ map[string]interface{}) {
}

func (m *mockAuditLogger) Close() error { return nil }

func (m *mockAuditLogger) getEvents() []*audit.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]*audit.Event, len(m.events))
	copy(result, m.events)
	return result
}

// auditTestServerStream implements grpc.ServerStream for audit testing.
type auditTestServerStream struct {
	ctx context.Context
}

func (m *auditTestServerStream) SetHeader(_ metadata.MD) error  { return nil }
func (m *auditTestServerStream) SendHeader(_ metadata.MD) error { return nil }
func (m *auditTestServerStream) SetTrailer(_ metadata.MD)       {}
func (m *auditTestServerStream) Context() context.Context       { return m.ctx }
func (m *auditTestServerStream) SendMsg(_ interface{}) error    { return nil }
func (m *auditTestServerStream) RecvMsg(_ interface{}) error    { return nil }

// ============================================================
// UnaryAuditInterceptor tests
// ============================================================

func TestUnaryAuditInterceptor_Success(t *testing.T) {
	t.Parallel()

	// Arrange
	logger := &mockAuditLogger{}
	interceptor := UnaryAuditInterceptor(logger)

	ctx := context.Background()
	ctx = peer.NewContext(ctx, &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 12345},
	})

	info := &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/GetUser",
	}

	handler := func(_ context.Context, _ interface{}) (interface{}, error) {
		return "response", nil
	}

	// Act
	resp, err := interceptor(ctx, "request", info, handler)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, "response", resp)

	events := logger.getEvents()
	require.Len(t, events, 2, "should log request and response events")

	// Verify request event
	reqEvent := events[0]
	assert.Equal(t, audit.EventTypeRequest, reqEvent.Type)
	assert.NotNil(t, reqEvent.Resource)
	assert.Equal(t, "grpc", reqEvent.Resource.Type)
	assert.Equal(t, "/test.Service/GetUser", reqEvent.Resource.Path)
	assert.Equal(t, "GetUser", reqEvent.Resource.Method)
	assert.Equal(t, "test.Service", reqEvent.Resource.Service)

	// Verify response event
	respEvent := events[1]
	assert.Equal(t, audit.EventTypeResponse, respEvent.Type)
	assert.Equal(t, audit.OutcomeSuccess, respEvent.Outcome)
	assert.Nil(t, respEvent.Error)
	assert.Greater(t, respEvent.Duration, time.Duration(0))
}

func TestUnaryAuditInterceptor_Error(t *testing.T) {
	t.Parallel()

	// Arrange
	logger := &mockAuditLogger{}
	interceptor := UnaryAuditInterceptor(logger)

	ctx := context.Background()
	ctx = peer.NewContext(ctx, &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 5000},
	})

	info := &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/FailMethod",
	}

	handler := func(_ context.Context, _ interface{}) (interface{}, error) {
		return nil, status.Error(codes.Internal, "internal error")
	}

	// Act
	resp, err := interceptor(ctx, "request", info, handler)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, resp)

	events := logger.getEvents()
	require.Len(t, events, 2)

	// Verify response event has error details
	respEvent := events[1]
	assert.Equal(t, audit.EventTypeResponse, respEvent.Type)
	assert.Equal(t, audit.OutcomeFailure, respEvent.Outcome)
	assert.NotNil(t, respEvent.Error)
	assert.Equal(t, codes.Internal.String(), respEvent.Error.Code)
	assert.Contains(t, respEvent.Error.Message, "internal error")
}

func TestUnaryAuditInterceptor_WithRequestID(t *testing.T) {
	t.Parallel()

	// Arrange
	logger := &mockAuditLogger{}
	interceptor := UnaryAuditInterceptor(logger)

	ctx := context.Background()
	ctx = observability.ContextWithRequestID(ctx, "test-request-id-123")
	ctx = peer.NewContext(ctx, &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080},
	})

	info := &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/Method",
	}

	handler := func(_ context.Context, _ interface{}) (interface{}, error) {
		return "ok", nil
	}

	// Act
	_, err := interceptor(ctx, "request", info, handler)

	// Assert
	require.NoError(t, err)

	events := logger.getEvents()
	require.Len(t, events, 2)

	// Both events should have request_id in metadata
	for _, event := range events {
		assert.Equal(t, "test-request-id-123", event.Metadata["request_id"])
	}
}

func TestUnaryAuditInterceptor_WithTraceContext(t *testing.T) {
	t.Parallel()

	// Arrange
	logger := &mockAuditLogger{}
	interceptor := UnaryAuditInterceptor(logger)

	// Note: Without a real OpenTelemetry span, TraceID/SpanID will be empty.
	// This test verifies the interceptor doesn't panic and still logs events.
	ctx := context.Background()
	ctx = peer.NewContext(ctx, &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080},
	})

	info := &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/Method",
	}

	handler := func(_ context.Context, _ interface{}) (interface{}, error) {
		return "ok", nil
	}

	// Act
	_, err := interceptor(ctx, "request", info, handler)

	// Assert
	require.NoError(t, err)

	events := logger.getEvents()
	require.Len(t, events, 2)
	// Without real trace context, TraceID and SpanID should be empty
	assert.Empty(t, events[0].TraceID)
	assert.Empty(t, events[0].SpanID)
}

// ============================================================
// StreamAuditInterceptor tests
// ============================================================

func TestStreamAuditInterceptor_Success(t *testing.T) {
	t.Parallel()

	// Arrange
	logger := &mockAuditLogger{}
	interceptor := StreamAuditInterceptor(logger)

	ctx := context.Background()
	ctx = peer.NewContext(ctx, &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 12345},
	})

	stream := &auditTestServerStream{ctx: ctx}
	info := &grpc.StreamServerInfo{
		FullMethod: "/test.Service/StreamMethod",
	}

	handler := func(_ interface{}, _ grpc.ServerStream) error {
		return nil
	}

	// Act
	err := interceptor(nil, stream, info, handler)

	// Assert
	require.NoError(t, err)

	events := logger.getEvents()
	require.Len(t, events, 2)

	// Verify request event
	reqEvent := events[0]
	assert.Equal(t, audit.EventTypeRequest, reqEvent.Type)
	assert.NotNil(t, reqEvent.Resource)
	assert.Equal(t, "grpc", reqEvent.Resource.Type)
	assert.Equal(t, "/test.Service/StreamMethod", reqEvent.Resource.Path)

	// Verify response event
	respEvent := events[1]
	assert.Equal(t, audit.EventTypeResponse, respEvent.Type)
	assert.Equal(t, audit.OutcomeSuccess, respEvent.Outcome)
	assert.Nil(t, respEvent.Error)
}

func TestStreamAuditInterceptor_Error(t *testing.T) {
	t.Parallel()

	// Arrange
	logger := &mockAuditLogger{}
	interceptor := StreamAuditInterceptor(logger)

	ctx := context.Background()
	ctx = peer.NewContext(ctx, &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 5000},
	})

	stream := &auditTestServerStream{ctx: ctx}
	info := &grpc.StreamServerInfo{
		FullMethod: "/test.Service/StreamFail",
	}

	handler := func(_ interface{}, _ grpc.ServerStream) error {
		return status.Error(codes.Unavailable, "service unavailable")
	}

	// Act
	err := interceptor(nil, stream, info, handler)

	// Assert
	assert.Error(t, err)

	events := logger.getEvents()
	require.Len(t, events, 2)

	// Verify response event has error details
	respEvent := events[1]
	assert.Equal(t, audit.OutcomeFailure, respEvent.Outcome)
	assert.NotNil(t, respEvent.Error)
	assert.Equal(t, codes.Unavailable.String(), respEvent.Error.Code)
	assert.Contains(t, respEvent.Error.Message, "service unavailable")
}

// ============================================================
// buildGRPCRequestEvent tests
// ============================================================

func TestBuildGRPCRequestEvent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		fullMethod string
		service    string
		method     string
		clientAddr string
		requestID  string
	}{
		{
			name:       "all fields populated",
			fullMethod: "/test.Service/GetUser",
			service:    "test.Service",
			method:     "GetUser",
			clientAddr: "192.168.1.1:12345",
			requestID:  "req-123",
		},
		{
			name:       "empty request ID",
			fullMethod: "/test.Service/ListUsers",
			service:    "test.Service",
			method:     "ListUsers",
			clientAddr: "10.0.0.1:5000",
			requestID:  "",
		},
		{
			name:       "empty client addr",
			fullMethod: "/pkg.Svc/Do",
			service:    "pkg.Svc",
			method:     "Do",
			clientAddr: "",
			requestID:  "req-456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Act
			event := buildGRPCRequestEvent(tt.fullMethod, tt.service, tt.method, tt.clientAddr, tt.requestID)

			// Assert
			require.NotNil(t, event)
			assert.Equal(t, audit.EventTypeRequest, event.Type)
			assert.NotEmpty(t, event.ID)
			assert.False(t, event.Timestamp.IsZero())

			// Verify resource
			require.NotNil(t, event.Resource)
			assert.Equal(t, "grpc", event.Resource.Type)
			assert.Equal(t, tt.fullMethod, event.Resource.Path)
			assert.Equal(t, tt.method, event.Resource.Method)
			assert.Equal(t, tt.service, event.Resource.Service)

			// Verify subject
			require.NotNil(t, event.Subject)
			assert.Equal(t, tt.clientAddr, event.Subject.IPAddress)

			// Verify request details
			require.NotNil(t, event.Request)
			assert.Equal(t, tt.method, event.Request.Method)
			assert.Equal(t, tt.fullMethod, event.Request.Path)
			assert.Equal(t, tt.clientAddr, event.Request.RemoteAddr)
			assert.Equal(t, "gRPC", event.Request.Protocol)

			// Verify request ID metadata
			if tt.requestID != "" {
				assert.Equal(t, tt.requestID, event.Metadata["request_id"])
			} else {
				_, exists := event.Metadata["request_id"]
				assert.False(t, exists, "request_id should not be in metadata when empty")
			}
		})
	}
}

// ============================================================
// buildGRPCResponseEvent tests
// ============================================================

func TestBuildGRPCResponseEvent_Success(t *testing.T) {
	t.Parallel()

	// Arrange
	duration := 150 * time.Millisecond

	// Act
	event := buildGRPCResponseEvent(
		"/test.Service/GetUser", "test.Service", "GetUser",
		"192.168.1.1:12345", "req-123",
		codes.OK, duration, nil,
	)

	// Assert
	require.NotNil(t, event)
	assert.Equal(t, audit.EventTypeResponse, event.Type)
	assert.Equal(t, audit.ActionGRPCResponse, event.Action)
	assert.Equal(t, audit.OutcomeSuccess, event.Outcome)
	assert.Equal(t, duration, event.Duration)

	// Verify resource
	require.NotNil(t, event.Resource)
	assert.Equal(t, "grpc", event.Resource.Type)
	assert.Equal(t, "/test.Service/GetUser", event.Resource.Path)
	assert.Equal(t, "GetUser", event.Resource.Method)
	assert.Equal(t, "test.Service", event.Resource.Service)

	// Verify subject
	require.NotNil(t, event.Subject)
	assert.Equal(t, "192.168.1.1:12345", event.Subject.IPAddress)

	// Verify response details
	require.NotNil(t, event.Response)
	assert.Equal(t, int(codes.OK), event.Response.StatusCode)

	// Verify no error
	assert.Nil(t, event.Error)

	// Verify request ID
	assert.Equal(t, "req-123", event.Metadata["request_id"])
}

func TestBuildGRPCResponseEvent_Error(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		grpcCode  codes.Code
		err       error
		requestID string
	}{
		{
			name:      "internal error",
			grpcCode:  codes.Internal,
			err:       status.Error(codes.Internal, "internal server error"),
			requestID: "req-err-1",
		},
		{
			name:      "not found error",
			grpcCode:  codes.NotFound,
			err:       status.Error(codes.NotFound, "resource not found"),
			requestID: "",
		},
		{
			name:      "permission denied",
			grpcCode:  codes.PermissionDenied,
			err:       status.Error(codes.PermissionDenied, "access denied"),
			requestID: "req-err-3",
		},
		{
			name:      "unavailable error",
			grpcCode:  codes.Unavailable,
			err:       status.Error(codes.Unavailable, "service unavailable"),
			requestID: "req-err-4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			duration := 50 * time.Millisecond

			// Act
			event := buildGRPCResponseEvent(
				"/test.Service/Method", "test.Service", "Method",
				"10.0.0.1:5000", tt.requestID,
				tt.grpcCode, duration, tt.err,
			)

			// Assert
			require.NotNil(t, event)
			assert.Equal(t, audit.EventTypeResponse, event.Type)
			assert.Equal(t, audit.OutcomeFailure, event.Outcome)

			// Verify error details
			require.NotNil(t, event.Error)
			assert.Equal(t, tt.grpcCode.String(), event.Error.Code)
			assert.Contains(t, event.Error.Message, tt.err.Error())

			// Verify request ID
			if tt.requestID != "" {
				assert.Equal(t, tt.requestID, event.Metadata["request_id"])
			}
		})
	}
}

// ============================================================
// enrichGRPCTraceContext tests
// ============================================================

func TestEnrichGRPCTraceContext(t *testing.T) {
	t.Parallel()

	// Arrange
	event := audit.NewEvent(audit.EventTypeRequest, audit.ActionGRPCRequest, audit.OutcomeSuccess)

	// Act
	enrichGRPCTraceContext(event, "trace-abc-123", "span-def-456")

	// Assert
	assert.Equal(t, "trace-abc-123", event.TraceID)
	assert.Equal(t, "span-def-456", event.SpanID)
}

func TestEnrichGRPCTraceContext_Empty(t *testing.T) {
	t.Parallel()

	// Arrange
	event := audit.NewEvent(audit.EventTypeRequest, audit.ActionGRPCRequest, audit.OutcomeSuccess)

	// Act
	enrichGRPCTraceContext(event, "", "")

	// Assert
	assert.Empty(t, event.TraceID)
	assert.Empty(t, event.SpanID)
}

func TestEnrichGRPCTraceContext_PartialTraceID(t *testing.T) {
	t.Parallel()

	// Arrange
	event := audit.NewEvent(audit.EventTypeRequest, audit.ActionGRPCRequest, audit.OutcomeSuccess)

	// Act — only traceID set
	enrichGRPCTraceContext(event, "trace-only", "")

	// Assert
	assert.Equal(t, "trace-only", event.TraceID)
	assert.Empty(t, event.SpanID)
}

func TestEnrichGRPCTraceContext_PartialSpanID(t *testing.T) {
	t.Parallel()

	// Arrange
	event := audit.NewEvent(audit.EventTypeRequest, audit.ActionGRPCRequest, audit.OutcomeSuccess)

	// Act — only spanID set
	enrichGRPCTraceContext(event, "", "span-only")

	// Assert
	assert.Empty(t, event.TraceID)
	assert.Equal(t, "span-only", event.SpanID)
}

// ============================================================
// getAuditRequestID tests
// ============================================================

func TestGetAuditRequestID_FromObservability(t *testing.T) {
	t.Parallel()

	// Arrange
	ctx := observability.ContextWithRequestID(context.Background(), "obs-request-id")

	// Act
	result := getAuditRequestID(ctx)

	// Assert
	assert.Equal(t, "obs-request-id", result)
}

func TestGetAuditRequestID_FromMetadata(t *testing.T) {
	t.Parallel()

	// Arrange
	ctx := metadata.NewIncomingContext(context.Background(), metadata.MD{
		RequestIDHeader: []string{"metadata-request-id"},
	})

	// Act
	result := getAuditRequestID(ctx)

	// Assert
	assert.Equal(t, "metadata-request-id", result)
}

func TestGetAuditRequestID_NotFound(t *testing.T) {
	t.Parallel()

	// Arrange
	ctx := context.Background()

	// Act
	result := getAuditRequestID(ctx)

	// Assert
	assert.Empty(t, result)
}

func TestGetAuditRequestID_ObservabilityTakesPrecedence(t *testing.T) {
	t.Parallel()

	// Arrange — both observability and metadata have request IDs
	ctx := observability.ContextWithRequestID(context.Background(), "obs-id")
	ctx = metadata.NewIncomingContext(ctx, metadata.MD{
		RequestIDHeader: []string{"metadata-id"},
	})

	// Act
	result := getAuditRequestID(ctx)

	// Assert — observability context should take precedence
	assert.Equal(t, "obs-id", result)
}

func TestGetAuditRequestID_EmptyObservabilityFallsToMetadata(t *testing.T) {
	t.Parallel()

	// Arrange — observability has empty request ID, metadata has one
	ctx := observability.ContextWithRequestID(context.Background(), "")
	ctx = metadata.NewIncomingContext(ctx, metadata.MD{
		RequestIDHeader: []string{"fallback-id"},
	})

	// Act
	result := getAuditRequestID(ctx)

	// Assert — should fall back to metadata
	assert.Equal(t, "fallback-id", result)
}

// ============================================================
// Table-driven integration tests
// ============================================================

func TestUnaryAuditInterceptor_TableDriven(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		fullMethod      string
		handlerErr      error
		expectOutcome   audit.Outcome
		expectErrorCode string
	}{
		{
			name:          "OK response",
			fullMethod:    "/svc.Foo/Bar",
			handlerErr:    nil,
			expectOutcome: audit.OutcomeSuccess,
		},
		{
			name:            "Internal error",
			fullMethod:      "/svc.Foo/Fail",
			handlerErr:      status.Error(codes.Internal, "boom"),
			expectOutcome:   audit.OutcomeFailure,
			expectErrorCode: codes.Internal.String(),
		},
		{
			name:            "NotFound error",
			fullMethod:      "/svc.Foo/Missing",
			handlerErr:      status.Error(codes.NotFound, "not found"),
			expectOutcome:   audit.OutcomeFailure,
			expectErrorCode: codes.NotFound.String(),
		},
		{
			name:            "PermissionDenied error",
			fullMethod:      "/svc.Foo/Denied",
			handlerErr:      status.Error(codes.PermissionDenied, "denied"),
			expectOutcome:   audit.OutcomeFailure,
			expectErrorCode: codes.PermissionDenied.String(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger := &mockAuditLogger{}
			interceptor := UnaryAuditInterceptor(logger)

			ctx := context.Background()
			ctx = peer.NewContext(ctx, &peer.Peer{
				Addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
			})

			info := &grpc.UnaryServerInfo{FullMethod: tt.fullMethod}
			handler := func(_ context.Context, _ interface{}) (interface{}, error) {
				return "resp", tt.handlerErr
			}

			_, _ = interceptor(ctx, "req", info, handler)

			events := logger.getEvents()
			require.Len(t, events, 2)

			respEvent := events[1]
			assert.Equal(t, tt.expectOutcome, respEvent.Outcome)

			if tt.expectErrorCode != "" {
				require.NotNil(t, respEvent.Error)
				assert.Equal(t, tt.expectErrorCode, respEvent.Error.Code)
			} else {
				assert.Nil(t, respEvent.Error)
			}
		})
	}
}

func TestStreamAuditInterceptor_TableDriven(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		fullMethod      string
		handlerErr      error
		expectOutcome   audit.Outcome
		expectErrorCode string
	}{
		{
			name:          "successful stream",
			fullMethod:    "/svc.Foo/StreamBar",
			handlerErr:    nil,
			expectOutcome: audit.OutcomeSuccess,
		},
		{
			name:            "stream error",
			fullMethod:      "/svc.Foo/StreamFail",
			handlerErr:      status.Error(codes.ResourceExhausted, "rate limited"),
			expectOutcome:   audit.OutcomeFailure,
			expectErrorCode: codes.ResourceExhausted.String(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger := &mockAuditLogger{}
			interceptor := StreamAuditInterceptor(logger)

			ctx := context.Background()
			ctx = peer.NewContext(ctx, &peer.Peer{
				Addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
			})

			stream := &auditTestServerStream{ctx: ctx}
			info := &grpc.StreamServerInfo{FullMethod: tt.fullMethod}
			handler := func(_ interface{}, _ grpc.ServerStream) error {
				return tt.handlerErr
			}

			_ = interceptor(nil, stream, info, handler)

			events := logger.getEvents()
			require.Len(t, events, 2)

			respEvent := events[1]
			assert.Equal(t, tt.expectOutcome, respEvent.Outcome)

			if tt.expectErrorCode != "" {
				require.NotNil(t, respEvent.Error)
				assert.Equal(t, tt.expectErrorCode, respEvent.Error.Code)
			} else {
				assert.Nil(t, respEvent.Error)
			}
		})
	}
}
