package proxy

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// mockServerStream implements grpc.ServerStream for testing
type mockServerStream struct {
	ctx         context.Context
	recvMsgs    []interface{}
	recvIdx     int
	recvErr     error
	sentMsgs    []interface{}
	sentHeader  metadata.MD
	sentTrailer metadata.MD
	sendErr     error
	mu          sync.Mutex
}

func newMockServerStream(ctx context.Context) *mockServerStream {
	return &mockServerStream{
		ctx:      ctx,
		sentMsgs: make([]interface{}, 0),
	}
}

func (m *mockServerStream) SetHeader(md metadata.MD) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sentHeader = md
	return nil
}

func (m *mockServerStream) SendHeader(md metadata.MD) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sentHeader = md
	return nil
}

func (m *mockServerStream) SetTrailer(md metadata.MD) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sentTrailer = md
}

func (m *mockServerStream) Context() context.Context {
	return m.ctx
}

func (m *mockServerStream) SendMsg(msg interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sendErr != nil {
		return m.sendErr
	}
	m.sentMsgs = append(m.sentMsgs, msg)
	return nil
}

func (m *mockServerStream) RecvMsg(msg interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.recvErr != nil {
		return m.recvErr
	}
	if m.recvIdx >= len(m.recvMsgs) {
		return io.EOF
	}
	// Copy payload to frame
	if frame, ok := msg.(*Frame); ok {
		if srcFrame, ok := m.recvMsgs[m.recvIdx].(*Frame); ok {
			frame.payload = srcFrame.payload
		}
	}
	m.recvIdx++
	return nil
}

// mockClientStream implements grpc.ClientStream for testing
type mockClientStreamForProxy struct {
	ctx          context.Context
	recvMsgs     []interface{}
	recvIdx      int
	recvErr      error
	sentMsgs     []interface{}
	sendErr      error
	headerMD     metadata.MD
	headerErr    error
	trailerMD    metadata.MD
	closeSendErr error
	mu           sync.Mutex
}

func newMockClientStream(ctx context.Context) *mockClientStreamForProxy {
	return &mockClientStreamForProxy{
		ctx:      ctx,
		sentMsgs: make([]interface{}, 0),
	}
}

func (m *mockClientStreamForProxy) Header() (metadata.MD, error) {
	return m.headerMD, m.headerErr
}

func (m *mockClientStreamForProxy) Trailer() metadata.MD {
	return m.trailerMD
}

func (m *mockClientStreamForProxy) CloseSend() error {
	return m.closeSendErr
}

func (m *mockClientStreamForProxy) Context() context.Context {
	return m.ctx
}

func (m *mockClientStreamForProxy) SendMsg(msg interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sendErr != nil {
		return m.sendErr
	}
	m.sentMsgs = append(m.sentMsgs, msg)
	return nil
}

func (m *mockClientStreamForProxy) RecvMsg(msg interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.recvErr != nil {
		return m.recvErr
	}
	if m.recvIdx >= len(m.recvMsgs) {
		return io.EOF
	}
	// Copy payload to frame
	if frame, ok := msg.(*Frame); ok {
		if srcFrame, ok := m.recvMsgs[m.recvIdx].(*Frame); ok {
			frame.payload = srcFrame.payload
		}
	}
	m.recvIdx++
	return nil
}

// mockDirector implements Director for testing
type mockDirector struct {
	outCtx    context.Context
	conn      *grpc.ClientConn
	directErr error
}

func (m *mockDirector) Direct(ctx context.Context, fullMethod string) (context.Context, *grpc.ClientConn, error) {
	if m.directErr != nil {
		return nil, nil, m.directErr
	}
	return m.outCtx, m.conn, nil
}

func TestNewStreamHandler(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	director := &mockDirector{}

	handler := NewStreamHandler(director, logger)

	assert.NotNil(t, handler)
	assert.Equal(t, director, handler.director)
	assert.NotNil(t, handler.logger)
}

func TestStreamHandler_HandleStream_NoMethodInContext(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	director := &mockDirector{}
	handler := NewStreamHandler(director, logger)

	// Context without method
	ctx := context.Background()
	stream := newMockServerStream(ctx)

	err := handler.HandleStream(nil, stream)
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
	assert.Contains(t, st.Message(), "failed to get method from context")
}

func TestStreamHandler_HandleStream_DirectorError(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	director := &mockDirector{
		directErr: errors.New("routing failed"),
	}
	handler := NewStreamHandler(director, logger)

	// Context with method
	ctx := grpc.NewContextWithServerTransportStream(
		context.Background(),
		&mockServerTransportStream{method: "/test.Service/Method"},
	)
	stream := newMockServerStream(ctx)

	err := handler.HandleStream(nil, stream)
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unavailable, st.Code())
	assert.Contains(t, st.Message(), "failed to route request")
}

func TestWrapServerStream(t *testing.T) {
	t.Parallel()

	originalCtx := context.Background()
	newCtx := context.WithValue(context.Background(), "key", "value")

	innerStream := newMockServerStream(originalCtx)
	wrappedStream := WrapServerStream(innerStream, newCtx)

	assert.NotNil(t, wrappedStream)
	assert.Equal(t, newCtx, wrappedStream.Context())
	assert.NotEqual(t, originalCtx, wrappedStream.Context())
}

func TestWrappedServerStream_Context(t *testing.T) {
	t.Parallel()

	ctx := context.WithValue(context.Background(), "testKey", "testValue")
	innerStream := newMockServerStream(context.Background())

	wrapped := &wrappedServerStream{
		ServerStream: innerStream,
		ctx:          ctx,
	}

	assert.Equal(t, ctx, wrapped.Context())
	assert.Equal(t, "testValue", wrapped.Context().Value("testKey"))
}

func TestWrappedServerStream_DelegatesMethods(t *testing.T) {
	t.Parallel()

	innerStream := newMockServerStream(context.Background())
	ctx := context.WithValue(context.Background(), "key", "value")

	wrapped := WrapServerStream(innerStream, ctx)

	// Test SetHeader
	err := wrapped.SetHeader(metadata.MD{"key": []string{"value"}})
	assert.NoError(t, err)

	// Test SendHeader
	err = wrapped.SendHeader(metadata.MD{"key2": []string{"value2"}})
	assert.NoError(t, err)

	// Test SetTrailer
	wrapped.SetTrailer(metadata.MD{"trailer": []string{"value"}})

	// Test SendMsg
	err = wrapped.SendMsg(&Frame{payload: []byte("test")})
	assert.NoError(t, err)

	// Test RecvMsg - will return EOF since no messages
	frame := &Frame{}
	err = wrapped.RecvMsg(frame)
	assert.Equal(t, io.EOF, err)
}

func TestStreamHandler_ForwardServerToClient_Success(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	director := &mockDirector{}
	handler := NewStreamHandler(director, logger)

	// Setup server stream with messages
	serverStream := newMockServerStream(context.Background())
	serverStream.recvMsgs = []interface{}{
		NewFrame([]byte("message1")),
		NewFrame([]byte("message2")),
	}

	// Setup client stream
	clientStream := newMockClientStream(context.Background())

	err := handler.forwardServerToClient(serverStream, clientStream)
	// Should return nil after CloseSend on EOF
	assert.NoError(t, err)

	// Verify messages were sent to client
	assert.Len(t, clientStream.sentMsgs, 2)
}

func TestStreamHandler_ForwardServerToClient_RecvError(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	director := &mockDirector{}
	handler := NewStreamHandler(director, logger)

	// Setup server stream with error
	serverStream := newMockServerStream(context.Background())
	serverStream.recvErr = errors.New("recv failed")

	clientStream := newMockClientStream(context.Background())

	err := handler.forwardServerToClient(serverStream, clientStream)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "recv failed")
}

func TestStreamHandler_ForwardServerToClient_SendError(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	director := &mockDirector{}
	handler := NewStreamHandler(director, logger)

	// Setup server stream with messages
	serverStream := newMockServerStream(context.Background())
	serverStream.recvMsgs = []interface{}{
		NewFrame([]byte("message1")),
	}

	// Setup client stream with send error
	clientStream := newMockClientStream(context.Background())
	clientStream.sendErr = errors.New("send failed")

	err := handler.forwardServerToClient(serverStream, clientStream)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "send failed")
}

func TestStreamHandler_ForwardClientToServer_Success(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	director := &mockDirector{}
	handler := NewStreamHandler(director, logger)

	// Setup client stream with messages
	clientStream := newMockClientStream(context.Background())
	clientStream.recvMsgs = []interface{}{
		NewFrame([]byte("response1")),
		NewFrame([]byte("response2")),
	}

	// Setup server stream
	serverStream := newMockServerStream(context.Background())

	err := handler.forwardClientToServer(clientStream, serverStream)
	assert.NoError(t, err)

	// Verify messages were sent to server
	assert.Len(t, serverStream.sentMsgs, 2)
}

func TestStreamHandler_ForwardClientToServer_RecvError(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	director := &mockDirector{}
	handler := NewStreamHandler(director, logger)

	// Setup client stream with error
	clientStream := newMockClientStream(context.Background())
	clientStream.recvErr = errors.New("recv failed")

	serverStream := newMockServerStream(context.Background())

	err := handler.forwardClientToServer(clientStream, serverStream)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "recv failed")
}

func TestStreamHandler_ForwardClientToServer_SendError(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	director := &mockDirector{}
	handler := NewStreamHandler(director, logger)

	// Setup client stream with messages
	clientStream := newMockClientStream(context.Background())
	clientStream.recvMsgs = []interface{}{
		NewFrame([]byte("response1")),
	}

	// Setup server stream with send error
	serverStream := newMockServerStream(context.Background())
	serverStream.sendErr = errors.New("send failed")

	err := handler.forwardClientToServer(clientStream, serverStream)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "send failed")
}

func TestStreamHandler_ProxyStreams_Success(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	director := &mockDirector{}
	handler := NewStreamHandler(director, logger)

	// Setup server stream (incoming requests)
	serverStream := newMockServerStream(context.Background())
	serverStream.recvMsgs = []interface{}{
		NewFrame([]byte("request1")),
	}

	// Setup client stream (backend responses)
	clientStream := newMockClientStream(context.Background())
	clientStream.recvMsgs = []interface{}{
		NewFrame([]byte("response1")),
	}
	clientStream.headerMD = metadata.MD{"x-backend": []string{"value"}}
	clientStream.trailerMD = metadata.MD{"x-trailer": []string{"value"}}

	err := handler.proxyStreams(serverStream, clientStream)
	assert.NoError(t, err)

	// Verify header was forwarded
	assert.NotNil(t, serverStream.sentHeader)

	// Verify trailer was set
	assert.NotNil(t, serverStream.sentTrailer)
}

func TestStreamHandler_ProxyStreams_ServerToClientError(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	director := &mockDirector{}
	handler := NewStreamHandler(director, logger)

	// Setup server stream with recv error
	serverStream := newMockServerStream(context.Background())
	serverStream.recvErr = status.Error(codes.Canceled, "canceled")

	// Setup client stream
	clientStream := newMockClientStream(context.Background())
	clientStream.recvMsgs = []interface{}{
		NewFrame([]byte("response1")),
	}

	err := handler.proxyStreams(serverStream, clientStream)
	assert.Error(t, err)
}

func TestStreamHandler_ProxyStreams_ClientToServerError(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	director := &mockDirector{}
	handler := NewStreamHandler(director, logger)

	// Setup server stream
	serverStream := newMockServerStream(context.Background())
	serverStream.recvMsgs = []interface{}{
		NewFrame([]byte("request1")),
	}

	// Setup client stream with recv error
	clientStream := newMockClientStream(context.Background())
	clientStream.recvErr = status.Error(codes.Internal, "backend error")
	clientStream.trailerMD = metadata.MD{"x-error": []string{"true"}}

	err := handler.proxyStreams(serverStream, clientStream)
	assert.Error(t, err)
}

func TestStreamHandler_ProxyStreams_HeaderError(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	director := &mockDirector{}
	handler := NewStreamHandler(director, logger)

	// Setup server stream
	serverStream := newMockServerStream(context.Background())
	serverStream.recvMsgs = []interface{}{
		NewFrame([]byte("request1")),
	}

	// Setup client stream with header error
	clientStream := newMockClientStream(context.Background())
	clientStream.headerErr = errors.New("header error")
	clientStream.recvMsgs = []interface{}{
		NewFrame([]byte("response1")),
	}

	// Should still work, header error is logged but not fatal
	err := handler.proxyStreams(serverStream, clientStream)
	assert.NoError(t, err)
}

// mockServerTransportStream implements grpc.ServerTransportStream for testing
type mockServerTransportStream struct {
	method string
}

func (m *mockServerTransportStream) Method() string {
	return m.method
}

func (m *mockServerTransportStream) SetHeader(md metadata.MD) error {
	return nil
}

func (m *mockServerTransportStream) SendHeader(md metadata.MD) error {
	return nil
}

func (m *mockServerTransportStream) SetTrailer(md metadata.MD) error {
	return nil
}

// Benchmarks

func BenchmarkStreamHandler_ForwardServerToClient(b *testing.B) {
	logger := observability.NopLogger()
	director := &mockDirector{}
	handler := NewStreamHandler(director, logger)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		serverStream := newMockServerStream(context.Background())
		serverStream.recvMsgs = []interface{}{
			NewFrame([]byte("message")),
		}
		clientStream := newMockClientStream(context.Background())

		_ = handler.forwardServerToClient(serverStream, clientStream)
	}
}

func BenchmarkStreamHandler_ForwardClientToServer(b *testing.B) {
	logger := observability.NopLogger()
	director := &mockDirector{}
	handler := NewStreamHandler(director, logger)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		clientStream := newMockClientStream(context.Background())
		clientStream.recvMsgs = []interface{}{
			NewFrame([]byte("response")),
		}
		serverStream := newMockServerStream(context.Background())

		_ = handler.forwardClientToServer(clientStream, serverStream)
	}
}

func TestStreamHandler_ForwardClientToServer_SendHeaderError(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	director := &mockDirector{}
	handler := NewStreamHandler(director, logger)

	// Setup client stream with messages and valid header
	clientStream := newMockClientStream(context.Background())
	clientStream.recvMsgs = []interface{}{
		NewFrame([]byte("response1")),
	}
	clientStream.headerMD = metadata.MD{"x-backend": []string{"value"}}

	// Setup server stream that fails on SendHeader
	serverStream := &mockServerStreamWithSendHeaderError{
		mockServerStream: newMockServerStream(context.Background()),
	}

	// Should still succeed — SendHeader error is logged but not fatal
	err := handler.forwardClientToServer(clientStream, serverStream)
	assert.NoError(t, err)

	// Verify message was still sent despite header error
	assert.Len(t, serverStream.mockServerStream.sentMsgs, 1)
}

// mockServerStreamWithSendHeaderError wraps mockServerStream but fails on SendHeader
type mockServerStreamWithSendHeaderError struct {
	*mockServerStream
}

func (m *mockServerStreamWithSendHeaderError) SendHeader(_ metadata.MD) error {
	return errors.New("send header failed")
}

func (m *mockServerStreamWithSendHeaderError) Context() context.Context {
	return m.mockServerStream.ctx
}

func (m *mockServerStreamWithSendHeaderError) SendMsg(msg interface{}) error {
	return m.mockServerStream.SendMsg(msg)
}

func (m *mockServerStreamWithSendHeaderError) RecvMsg(msg interface{}) error {
	return m.mockServerStream.RecvMsg(msg)
}

func (m *mockServerStreamWithSendHeaderError) SetTrailer(md metadata.MD) {
	m.mockServerStream.SetTrailer(md)
}

func TestStreamHandler_ForwardClientToServer_NilHeader(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	director := &mockDirector{}
	handler := NewStreamHandler(director, logger)

	// Setup client stream with messages but nil header
	clientStream := newMockClientStream(context.Background())
	clientStream.recvMsgs = []interface{}{
		NewFrame([]byte("response1")),
	}
	clientStream.headerMD = nil // nil header

	// Setup server stream
	serverStream := newMockServerStream(context.Background())

	err := handler.forwardClientToServer(clientStream, serverStream)
	assert.NoError(t, err)

	// Verify message was sent
	assert.Len(t, serverStream.sentMsgs, 1)
	// Header should not have been sent (nil header)
	assert.Nil(t, serverStream.sentHeader)
}

func TestStreamHandler_ForwardClientToServer_MultipleMessages(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	director := &mockDirector{}
	handler := NewStreamHandler(director, logger)

	// Setup client stream with multiple messages
	clientStream := newMockClientStream(context.Background())
	clientStream.recvMsgs = []interface{}{
		NewFrame([]byte("response1")),
		NewFrame([]byte("response2")),
		NewFrame([]byte("response3")),
	}
	clientStream.headerMD = metadata.MD{"x-backend": []string{"value"}}

	// Setup server stream
	serverStream := newMockServerStream(context.Background())

	err := handler.forwardClientToServer(clientStream, serverStream)
	assert.NoError(t, err)

	// Verify all messages were sent
	assert.Len(t, serverStream.sentMsgs, 3)
	// Header should only be sent once (before first message)
	assert.NotNil(t, serverStream.sentHeader)
}

func BenchmarkWrapServerStream(b *testing.B) {
	innerStream := newMockServerStream(context.Background())
	ctx := context.WithValue(context.Background(), "key", "value")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = WrapServerStream(innerStream, ctx)
	}
}
