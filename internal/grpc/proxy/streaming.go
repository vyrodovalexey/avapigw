package proxy

import (
	"context"
	"io"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// StreamHandler handles gRPC stream proxying.
type StreamHandler struct {
	director Director
	logger   observability.Logger
}

// NewStreamHandler creates a new stream handler.
func NewStreamHandler(director Director, logger observability.Logger) *StreamHandler {
	return &StreamHandler{
		director: director,
		logger:   logger,
	}
}

// HandleStream handles all types of gRPC streams (unary, server, client, bidi).
func (h *StreamHandler) HandleStream(srv interface{}, serverStream grpc.ServerStream) error {
	ctx := serverStream.Context()

	// Get full method from context
	fullMethod, ok := grpc.Method(ctx)
	if !ok {
		return status.Error(codes.Internal, "failed to get method from context")
	}

	// Get backend connection
	outCtx, conn, err := h.director.Direct(ctx, fullMethod)
	if err != nil {
		h.logger.Error("failed to direct request",
			observability.String("method", fullMethod),
			observability.Error(err),
		)
		return status.Errorf(codes.Unavailable, "failed to route request: %v", err)
	}

	// Create client stream to backend
	clientStream, err := h.createClientStream(outCtx, conn, fullMethod)
	if err != nil {
		h.logger.Error("failed to create client stream",
			observability.String("method", fullMethod),
			observability.Error(err),
		)
		return err
	}

	// Proxy the streams bidirectionally
	return h.proxyStreams(serverStream, clientStream)
}

// createClientStream creates a client stream to the backend.
func (h *StreamHandler) createClientStream(
	ctx context.Context, conn *grpc.ClientConn, fullMethod string,
) (grpc.ClientStream, error) {
	// Create stream descriptor for unknown service
	desc := &grpc.StreamDesc{
		StreamName:    fullMethod,
		ServerStreams: true,
		ClientStreams: true,
	}

	return conn.NewStream(ctx, desc, fullMethod)
}

// proxyStreams proxies data between server and client streams.
func (h *StreamHandler) proxyStreams(serverStream grpc.ServerStream, clientStream grpc.ClientStream) error {
	// Forward server header metadata to client
	if md, err := clientStream.Header(); err == nil && md != nil {
		if err := serverStream.SendHeader(md); err != nil {
			h.logger.Debug("failed to send header",
				observability.Error(err),
			)
		}
	}

	// Create error channels for bidirectional streaming
	serverToClientErr := make(chan error, 1)
	clientToServerErr := make(chan error, 1)

	// Server -> Client (request direction)
	go func() {
		serverToClientErr <- h.forwardServerToClient(serverStream, clientStream)
	}()

	// Client -> Server (response direction)
	go func() {
		clientToServerErr <- h.forwardClientToServer(clientStream, serverStream)
	}()

	// Wait for both directions to complete
	// The first error (or completion) determines the result
	for i := 0; i < 2; i++ {
		select {
		case err := <-serverToClientErr:
			if err != nil && err != io.EOF {
				// Close send on client stream
				_ = clientStream.CloseSend()
				return err
			}
		case err := <-clientToServerErr:
			// Set trailer metadata
			serverStream.SetTrailer(clientStream.Trailer())
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// forwardServerToClient forwards messages from server stream to client stream.
func (h *StreamHandler) forwardServerToClient(serverStream grpc.ServerStream, clientStream grpc.ClientStream) error {
	for {
		frame := &Frame{}
		if err := serverStream.RecvMsg(frame); err != nil {
			if err == io.EOF {
				// Close send on client stream
				return clientStream.CloseSend()
			}
			return err
		}

		if err := clientStream.SendMsg(frame); err != nil {
			return err
		}
	}
}

// forwardClientToServer forwards messages from client stream to server stream.
func (h *StreamHandler) forwardClientToServer(clientStream grpc.ClientStream, serverStream grpc.ServerStream) error {
	for {
		frame := &Frame{}
		if err := clientStream.RecvMsg(frame); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		if err := serverStream.SendMsg(frame); err != nil {
			return err
		}
	}
}

// wrappedServerStream wraps a grpc.ServerStream to allow context modification.
type wrappedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

// Context returns the wrapped context.
func (w *wrappedServerStream) Context() context.Context {
	return w.ctx
}

// WrapServerStream wraps a server stream with a new context.
func WrapServerStream(stream grpc.ServerStream, ctx context.Context) grpc.ServerStream {
	return &wrappedServerStream{
		ServerStream: stream,
		ctx:          ctx,
	}
}
