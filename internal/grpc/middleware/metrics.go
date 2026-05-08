package middleware

import (
	"context"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/vyrodovalexey/avapigw/internal/grpc/router"
)

// Metric/label constants.
const (
	labelService = "service"
)

// Metric label constants.
const (
	resourceTypeGRPC = "grpc"
	subsystemServer  = "server"
	labelMethod      = "method"
)

// GRPCMetrics holds Prometheus metrics for gRPC.
type GRPCMetrics struct {
	requestsTotal      *prometheus.CounterVec
	requestDuration    *prometheus.HistogramVec
	streamMsgsSent     *prometheus.CounterVec
	streamMsgsReceived *prometheus.CounterVec
	activeStreams      *prometheus.GaugeVec
	registry           *prometheus.Registry
}

// NewGRPCMetrics creates a new GRPCMetrics instance.
func NewGRPCMetrics(namespace string, registry *prometheus.Registry) *GRPCMetrics {
	if namespace == "" {
		namespace = resourceTypeGRPC
	}

	if registry == nil {
		registry = prometheus.DefaultRegisterer.(*prometheus.Registry)
	}

	m := &GRPCMetrics{
		registry: registry,
	}

	m.requestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: subsystemServer,
			Name:      "requests_total",
			Help:      "Total number of gRPC requests",
		},
		[]string{labelService, labelMethod, "code"},
	)

	m.requestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: subsystemServer,
			Name:      "request_duration_seconds",
			Help:      "gRPC request duration in seconds",
			Buckets:   []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
		},
		[]string{labelService, labelMethod, "code"},
	)

	m.streamMsgsSent = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: subsystemServer,
			Name:      "stream_messages_sent_total",
			Help:      "Total number of gRPC stream messages sent",
		},
		[]string{labelService, labelMethod},
	)

	m.streamMsgsReceived = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: subsystemServer,
			Name:      "stream_messages_received_total",
			Help:      "Total number of gRPC stream messages received",
		},
		[]string{labelService, labelMethod},
	)

	m.activeStreams = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystemServer,
			Name:      "active_streams",
			Help:      "Number of active gRPC streams",
		},
		[]string{labelService, labelMethod},
	)

	// Register metrics
	registry.MustRegister(
		m.requestsTotal,
		m.requestDuration,
		m.streamMsgsSent,
		m.streamMsgsReceived,
		m.activeStreams,
	)

	return m
}

// RecordRequest records a completed gRPC request.
func (m *GRPCMetrics) RecordRequest(service, method string, code codes.Code, duration time.Duration) {
	codeStr := strconv.Itoa(int(code))
	m.requestsTotal.WithLabelValues(service, method, codeStr).Inc()
	m.requestDuration.WithLabelValues(service, method, codeStr).Observe(duration.Seconds())
}

// RecordStreamMsgSent records a sent stream message.
func (m *GRPCMetrics) RecordStreamMsgSent(service, method string) {
	m.streamMsgsSent.WithLabelValues(service, method).Inc()
}

// RecordStreamMsgReceived records a received stream message.
func (m *GRPCMetrics) RecordStreamMsgReceived(service, method string) {
	m.streamMsgsReceived.WithLabelValues(service, method).Inc()
}

// IncrementActiveStreams increments the active streams gauge.
func (m *GRPCMetrics) IncrementActiveStreams(service, method string) {
	m.activeStreams.WithLabelValues(service, method).Inc()
}

// DecrementActiveStreams decrements the active streams gauge.
func (m *GRPCMetrics) DecrementActiveStreams(service, method string) {
	m.activeStreams.WithLabelValues(service, method).Dec()
}

// UnaryMetricsInterceptor returns a unary server interceptor that records metrics.
func UnaryMetricsInterceptor(metrics *GRPCMetrics) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		start := time.Now()

		// Extract service and method
		service, method := router.ParseFullMethod(info.FullMethod)

		// Call handler
		resp, err := handler(ctx, req)

		// Record metrics
		duration := time.Since(start)
		code := codes.OK
		if err != nil {
			code = status.Code(err)
		}

		metrics.RecordRequest(service, method, code, duration)

		return resp, err
	}
}

// StreamMetricsInterceptor returns a stream server interceptor that records metrics.
func StreamMetricsInterceptor(metrics *GRPCMetrics) grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		stream grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		start := time.Now()

		// Extract service and method
		service, method := router.ParseFullMethod(info.FullMethod)

		// Track active streams
		metrics.IncrementActiveStreams(service, method)
		defer metrics.DecrementActiveStreams(service, method)

		// Wrap stream to count messages
		wrapped := &metricsServerStream{
			ServerStream: stream,
			metrics:      metrics,
			service:      service,
			method:       method,
		}

		// Call handler
		err := handler(srv, wrapped)

		// Record metrics
		duration := time.Since(start)
		code := codes.OK
		if err != nil {
			code = status.Code(err)
		}

		metrics.RecordRequest(service, method, code, duration)

		return err
	}
}

// metricsServerStream wraps grpc.ServerStream to record message metrics.
type metricsServerStream struct {
	grpc.ServerStream
	metrics *GRPCMetrics
	service string
	method  string
}

// SendMsg records sent messages.
func (s *metricsServerStream) SendMsg(m interface{}) error {
	err := s.ServerStream.SendMsg(m)
	if err == nil {
		s.metrics.RecordStreamMsgSent(s.service, s.method)
	}
	return err
}

// RecvMsg records received messages.
func (s *metricsServerStream) RecvMsg(m interface{}) error {
	err := s.ServerStream.RecvMsg(m)
	if err == nil {
		s.metrics.RecordStreamMsgReceived(s.service, s.method)
	}
	return err
}
