// Package grpc provides gRPC server and client for operator-gateway communication.
package grpc

import (
	"context"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

var (
	defaultGRPCServerMetrics     *grpcServerMetrics
	defaultGRPCServerMetricsOnce sync.Once
)

// grpcServerMetrics holds Prometheus metrics for gRPC server interceptors.
// These metrics track request counts, durations, active streams, and stream message
// throughput for the operator's ConfigurationService gRPC server.
type grpcServerMetrics struct {
	requestsTotal     *prometheus.CounterVec
	requestDuration   *prometheus.HistogramVec
	activeStreams     prometheus.Gauge
	streamMsgSent     *prometheus.CounterVec
	streamMsgReceived *prometheus.CounterVec
}

// initGRPCServerMetrics initializes the singleton gRPC server metrics instance
// with the given Prometheus registerer. If registerer is nil, metrics are
// registered with the default registerer. Must be called before
// getGRPCServerMetrics; subsequent calls are no-ops (sync.Once).
func initGRPCServerMetrics(registerer prometheus.Registerer) {
	defaultGRPCServerMetricsOnce.Do(func() {
		if registerer == nil {
			registerer = prometheus.DefaultRegisterer
		}
		defaultGRPCServerMetrics = newGRPCServerMetricsWithFactory(
			promauto.With(registerer),
		)
	})
}

// getGRPCServerMetrics returns the singleton gRPC server metrics instance.
// If initGRPCServerMetrics has not been called, metrics are lazily
// initialized with the default registerer.
func getGRPCServerMetrics() *grpcServerMetrics {
	initGRPCServerMetrics(nil)
	return defaultGRPCServerMetrics
}

// newGRPCServerMetricsWithFactory creates gRPC server metrics using the given promauto factory.
// This allows tests to supply a custom registry to avoid duplicate registration panics.
func newGRPCServerMetricsWithFactory(factory promauto.Factory) *grpcServerMetrics {
	return &grpcServerMetrics{
		requestsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "avapigw_operator",
				Subsystem: "grpc_server",
				Name:      "requests_total",
				Help:      "Total number of gRPC server requests",
			},
			[]string{"method", "code"},
		),
		requestDuration: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "avapigw_operator",
				Subsystem: "grpc_server",
				Name:      "request_duration_seconds",
				Help:      "gRPC server request duration in seconds",
				Buckets:   []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5},
			},
			[]string{"method"},
		),
		activeStreams: factory.NewGauge(
			prometheus.GaugeOpts{
				Namespace: "avapigw_operator",
				Subsystem: "grpc_server",
				Name:      "active_streams",
				Help:      "Number of currently active gRPC server streams",
			},
		),
		streamMsgSent: factory.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "avapigw_operator",
				Subsystem: "grpc_server",
				Name:      "stream_messages_sent_total",
				Help:      "Total number of gRPC server stream messages sent",
			},
			[]string{"method"},
		),
		streamMsgReceived: factory.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "avapigw_operator",
				Subsystem: "grpc_server",
				Name:      "stream_messages_received_total",
				Help:      "Total number of gRPC server stream messages received",
			},
			[]string{"method"},
		),
	}
}

// UnaryServerInterceptor returns a gRPC unary server interceptor that records
// request count, duration, and status code metrics for each unary RPC call.
func (m *grpcServerMetrics) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		start := time.Now()

		resp, err := handler(ctx, req)

		// Record request duration
		duration := time.Since(start)
		m.requestDuration.WithLabelValues(info.FullMethod).Observe(duration.Seconds())

		// Extract gRPC status code from the error
		st, _ := status.FromError(err)
		code := st.Code().String()
		m.requestsTotal.WithLabelValues(info.FullMethod, code).Inc()

		return resp, err
	}
}

// StreamServerInterceptor returns a gRPC stream server interceptor that tracks
// active streams, wraps the stream to count sent/received messages, and records
// request count and duration metrics for each streaming RPC call.
func (m *grpcServerMetrics) StreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		stream grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		start := time.Now()

		// Track active streams
		m.activeStreams.Inc()
		defer m.activeStreams.Dec()

		// Wrap stream to count sent/received messages
		wrapped := &wrappedServerStream{
			ServerStream: stream,
			method:       info.FullMethod,
			metrics:      m,
		}

		err := handler(srv, wrapped)

		// Record request duration
		duration := time.Since(start)
		m.requestDuration.WithLabelValues(info.FullMethod).Observe(duration.Seconds())

		// Extract gRPC status code from the error
		st, _ := status.FromError(err)
		code := st.Code().String()
		m.requestsTotal.WithLabelValues(info.FullMethod, code).Inc()

		return err
	}
}

// wrappedServerStream wraps grpc.ServerStream to intercept SendMsg and RecvMsg
// calls for counting stream message throughput metrics.
type wrappedServerStream struct {
	grpc.ServerStream
	method  string
	metrics *grpcServerMetrics
}

// SendMsg intercepts outgoing stream messages and increments the sent counter
// on successful sends.
func (w *wrappedServerStream) SendMsg(m interface{}) error {
	err := w.ServerStream.SendMsg(m)
	if err == nil {
		w.metrics.streamMsgSent.WithLabelValues(w.method).Inc()
	}
	return err
}

// RecvMsg intercepts incoming stream messages and increments the received counter
// on successful receives.
func (w *wrappedServerStream) RecvMsg(m interface{}) error {
	err := w.ServerStream.RecvMsg(m)
	if err == nil {
		w.metrics.streamMsgReceived.WithLabelValues(w.method).Inc()
	}
	return err
}
