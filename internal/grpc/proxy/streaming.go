package proxy

import (
	"context"
	"errors"
	"io"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/grpc/transform"
	"github.com/vyrodovalexey/avapigw/internal/metrics/streaming"
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
// The optional routeCfg parameter provides the matched route configuration
// for applying per-route transforms. When nil, no transforms are applied.
func (h *StreamHandler) HandleStream(
	srv interface{}, serverStream grpc.ServerStream, routeCfg *config.GRPCRoute,
) error {
	ctx := serverStream.Context()

	// Get full method from context
	fullMethod, ok := grpc.Method(ctx)
	if !ok {
		return status.Error(codes.Internal, "failed to get method from context")
	}

	// Record gRPC stream start (new streaming metrics package).
	// Route name is derived from the full method for gRPC.
	grpcStreamMetrics := streaming.GetGRPCStreamMetrics()
	grpcStreamMetrics.RecordStreamStart(fullMethod, fullMethod)
	streamStart := time.Now()
	defer func() {
		grpcStreamMetrics.RecordStreamEnd(
			fullMethod, fullMethod, time.Since(streamStart),
		)
	}()

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

	// Proxy the streams bidirectionally with optional route transforms
	return h.proxyStreams(serverStream, clientStream, routeCfg)
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
// The optional routeCfg provides route configuration for applying response transforms.
func (h *StreamHandler) proxyStreams(
	serverStream grpc.ServerStream, clientStream grpc.ClientStream, routeCfg *config.GRPCRoute,
) error {
	// NOTE: We do NOT call clientStream.Header() here because it blocks until
	// the backend sends headers. For unary calls, the backend only sends headers
	// after receiving the request, which would cause a deadlock.
	// Instead, headers are forwarded in forwardClientToServer after the first response.

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
			if err != nil && !errors.Is(err, io.EOF) {
				// Close send on client stream
				_ = clientStream.CloseSend()
				return err
			}
		case err := <-clientToServerErr:
			// Apply response trailer transforms before setting trailers
			trailers := clientStream.Trailer()
			trailers = h.applyResponseTrailerTransforms(
				serverStream.Context(), trailers, routeCfg,
			)
			serverStream.SetTrailer(trailers)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// forwardServerToClient forwards messages from server stream to client stream.
func (h *StreamHandler) forwardServerToClient(serverStream grpc.ServerStream, clientStream grpc.ClientStream) error {
	metrics := getGRPCProxyMetrics()
	grpcStreamMetrics := streaming.GetGRPCStreamMetrics()
	fullMethod, _ := grpc.Method(serverStream.Context())

	for {
		frame := &Frame{}
		if err := serverStream.RecvMsg(frame); err != nil {
			if errors.Is(err, io.EOF) {
				// Close send on client stream
				return clientStream.CloseSend()
			}
			return err
		}

		// Record request message size and count (old metrics)
		metrics.requestSize.WithLabelValues(fullMethod).Observe(float64(len(frame.payload)))
		metrics.streamMsgSent.WithLabelValues(fullMethod).Inc()

		// Record streaming-level message sent to backend (new metrics)
		grpcStreamMetrics.RecordMessageSent(
			fullMethod, fullMethod, int64(len(frame.payload)),
		)

		if err := clientStream.SendMsg(frame); err != nil {
			return err
		}
	}
}

// forwardClientToServer forwards messages from client stream to server stream.
func (h *StreamHandler) forwardClientToServer(
	clientStream grpc.ClientStream, serverStream grpc.ServerStream,
) error {
	metrics := getGRPCProxyMetrics()
	grpcStreamMetrics := streaming.GetGRPCStreamMetrics()
	fullMethod, _ := grpc.Method(serverStream.Context())

	headerSent := false
	for {
		frame := &Frame{}
		if err := clientStream.RecvMsg(frame); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}

		// Record response message size and count (old metrics)
		metrics.responseSize.WithLabelValues(fullMethod).Observe(float64(len(frame.payload)))
		metrics.streamMsgReceived.WithLabelValues(fullMethod).Inc()

		// Record streaming-level message received from backend (new metrics)
		grpcStreamMetrics.RecordMessageReceived(
			fullMethod, fullMethod, int64(len(frame.payload)),
		)

		// Forward headers before the first message (non-blocking after first RecvMsg)
		if !headerSent {
			headerSent = true
			if md, headerErr := clientStream.Header(); headerErr == nil && md != nil {
				if sendErr := serverStream.SendHeader(md); sendErr != nil {
					h.logger.Debug("failed to send header",
						observability.Error(sendErr),
					)
				}
			}
		}

		if err := serverStream.SendMsg(frame); err != nil {
			return err
		}
	}
}

// applyResponseTrailerTransforms applies response trailer metadata transforms
// from the route configuration. It adds trailer metadata from the route's
// Transform.Response.TrailerMetadata config.
func (h *StreamHandler) applyResponseTrailerTransforms(
	ctx context.Context, trailers metadata.MD, routeCfg *config.GRPCRoute,
) metadata.MD {
	if routeCfg == nil || routeCfg.Transform == nil || routeCfg.Transform.Response == nil {
		return trailers
	}

	responseCfg := routeCfg.Transform.Response
	if len(responseCfg.TrailerMetadata) == 0 {
		return trailers
	}

	metrics := getGRPCProxyMetrics()
	transformer := transform.NewMetadataTransformer(h.logger)

	transformed, err := transformer.TransformTrailerMetadata(ctx, trailers, responseCfg)
	if err != nil {
		h.logger.Warn("failed to apply response trailer transforms",
			observability.String("route", routeCfg.Name),
			observability.Error(err),
		)
		return trailers
	}

	metrics.transformOperations.WithLabelValues(
		routeCfg.Name, "response", "trailer_metadata",
	).Inc()

	h.logger.Debug("applied response trailer transforms",
		observability.String("route", routeCfg.Name),
		observability.Int("trailer_count", len(responseCfg.TrailerMetadata)),
	)

	return transformed
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
