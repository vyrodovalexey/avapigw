package proxy

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// grpcProxyMetrics contains Prometheus metrics for gRPC proxy operations.
type grpcProxyMetrics struct {
	poolSize          prometheus.Gauge
	connectionCreated *prometheus.CounterVec
	connectionErrors  *prometheus.CounterVec
	connectionClosed  *prometheus.CounterVec
	directRequests    *prometheus.CounterVec
	directDuration    *prometheus.HistogramVec

	// DEV-005: additional metrics for comprehensive gRPC proxy observability.
	requestSize        *prometheus.HistogramVec
	responseSize       *prometheus.HistogramVec
	streamMsgSent      *prometheus.CounterVec
	streamMsgReceived  *prometheus.CounterVec
	backendSelections  *prometheus.CounterVec
	timeoutOccurrences *prometheus.CounterVec
}

var (
	grpcProxyMetricsInstance *grpcProxyMetrics
	grpcProxyMetricsOnce     sync.Once
)

// InitGRPCProxyMetrics initializes the singleton gRPC proxy metrics
// instance with the given Prometheus registry. If registry is nil,
// metrics are registered with the default registerer. Must be called
// before getGRPCProxyMetrics; subsequent calls are no-ops (sync.Once).
//
//nolint:funlen // metric initialization requires many declarations
func InitGRPCProxyMetrics(registry *prometheus.Registry) {
	grpcProxyMetricsOnce.Do(func() {
		var registerer prometheus.Registerer
		if registry != nil {
			registerer = registry
		} else {
			registerer = prometheus.DefaultRegisterer
		}
		factory := promauto.With(registerer)
		grpcProxyMetricsInstance = &grpcProxyMetrics{
			poolSize: factory.NewGauge(
				prometheus.GaugeOpts{
					Namespace: "gateway",
					Subsystem: "grpc_proxy",
					Name:      "pool_connections",
					Help:      "Current number of connections in the gRPC connection pool",
				},
			),
			connectionCreated: factory.NewCounterVec(
				prometheus.CounterOpts{
					Namespace: "gateway",
					Subsystem: "grpc_proxy",
					Name:      "connections_created_total",
					Help:      "Total number of gRPC connections created",
				},
				[]string{"target"},
			),
			connectionErrors: factory.NewCounterVec(
				prometheus.CounterOpts{
					Namespace: "gateway",
					Subsystem: "grpc_proxy",
					Name:      "connection_errors_total",
					Help:      "Total number of gRPC connection errors",
				},
				[]string{"target", "error_type"},
			),
			connectionClosed: factory.NewCounterVec(
				prometheus.CounterOpts{
					Namespace: "gateway",
					Subsystem: "grpc_proxy",
					Name:      "connections_closed_total",
					Help:      "Total number of gRPC connections closed",
				},
				[]string{"target"},
			),
			directRequests: factory.NewCounterVec(
				prometheus.CounterOpts{
					Namespace: "gateway",
					Subsystem: "grpc_proxy",
					Name:      "direct_requests_total",
					Help:      "Total number of gRPC proxy direct requests",
				},
				[]string{"method", "result"},
			),
			directDuration: factory.NewHistogramVec(
				prometheus.HistogramOpts{
					Namespace: "gateway",
					Subsystem: "grpc_proxy",
					Name:      "direct_duration_seconds",
					Help:      "Duration of gRPC proxy direct operations in seconds",
					Buckets: []float64{
						.001, .005, .01, .025,
						.05, .1, .25, .5,
						1, 2.5, 5, 10,
					},
				},
				[]string{"method"},
			),
			requestSize: factory.NewHistogramVec(
				prometheus.HistogramOpts{
					Namespace: "gateway",
					Subsystem: "grpc_proxy",
					Name:      "request_size_bytes",
					Help:      "Size of gRPC proxy request messages in bytes",
					Buckets:   prometheus.ExponentialBuckets(64, 4, 10),
				},
				[]string{"method"},
			),
			responseSize: factory.NewHistogramVec(
				prometheus.HistogramOpts{
					Namespace: "gateway",
					Subsystem: "grpc_proxy",
					Name:      "response_size_bytes",
					Help:      "Size of gRPC proxy response messages in bytes",
					Buckets:   prometheus.ExponentialBuckets(64, 4, 10),
				},
				[]string{"method"},
			),
			streamMsgSent: factory.NewCounterVec(
				prometheus.CounterOpts{
					Namespace: "gateway",
					Subsystem: "grpc_proxy",
					Name:      "stream_messages_sent_total",
					Help:      "Total number of gRPC stream messages sent to backend",
				},
				[]string{"method"},
			),
			streamMsgReceived: factory.NewCounterVec(
				prometheus.CounterOpts{
					Namespace: "gateway",
					Subsystem: "grpc_proxy",
					Name:      "stream_messages_received_total",
					Help:      "Total number of gRPC stream messages received from backend",
				},
				[]string{"method"},
			),
			backendSelections: factory.NewCounterVec(
				prometheus.CounterOpts{
					Namespace: "gateway",
					Subsystem: "grpc_proxy",
					Name:      "backend_selections_total",
					Help:      "Total number of backend selection decisions",
				},
				[]string{"route", "target", "strategy"},
			),
			timeoutOccurrences: factory.NewCounterVec(
				prometheus.CounterOpts{
					Namespace: "gateway",
					Subsystem: "grpc_proxy",
					Name:      "timeout_total",
					Help:      "Total number of gRPC proxy timeout occurrences",
				},
				[]string{"method"},
			),
		}
	})
}

// InitGRPCProxyVecMetrics pre-populates common label combinations
// with zero values so that gRPC proxy Vec metrics appear in /metrics
// output immediately after startup. Must be called after
// InitGRPCProxyMetrics.
func InitGRPCProxyVecMetrics() {
	m := getGRPCProxyMetrics()

	errorTypes := []string{
		"dial_error",
		"tls_error",
		"auth_error",
	}
	for _, et := range errorTypes {
		m.connectionErrors.WithLabelValues("default", et)
	}

	m.connectionClosed.WithLabelValues("default")
	m.timeoutOccurrences.WithLabelValues("default")
}

// getGRPCProxyMetrics returns the singleton gRPC proxy metrics instance.
// If InitGRPCProxyMetrics has not been called, metrics are lazily
// initialized with the default registerer.
func getGRPCProxyMetrics() *grpcProxyMetrics {
	InitGRPCProxyMetrics(nil)
	return grpcProxyMetricsInstance
}
