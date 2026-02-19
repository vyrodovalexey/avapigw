// Package streaming provides standardized Prometheus metrics for
// WebSocket and gRPC streaming observability in the API Gateway.
package streaming

import (
	"errors"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// WSMetrics holds all WebSocket-level Prometheus metrics.
type WSMetrics struct {
	ConnectionsTotal          *prometheus.CounterVec
	ConnectionsActive         *prometheus.GaugeVec
	MessagesSentTotal         *prometheus.CounterVec
	MessagesReceivedTotal     *prometheus.CounterVec
	ErrorsTotal               *prometheus.CounterVec
	ConnectionDurationSeconds *prometheus.HistogramVec
	MessageSizeBytes          *prometheus.HistogramVec
}

// GRPCStreamMetrics holds all gRPC streaming Prometheus metrics.
type GRPCStreamMetrics struct {
	MessagesSentTotal     *prometheus.CounterVec
	MessagesReceivedTotal *prometheus.CounterVec
	Active                *prometheus.GaugeVec
	DurationSeconds       *prometheus.HistogramVec
	MessageSizeBytes      *prometheus.HistogramVec
}

var (
	wsMetricsInstance   *WSMetrics
	wsMetricsOnce       sync.Once
	grpcMetricsInstance *GRPCStreamMetrics
	grpcMetricsOnce     sync.Once
)

// defaultLabel is the label value used for pre-populating metrics
// during Init().
const defaultLabel = "default"

// sizeBuckets defines histogram buckets for message sizes:
// 100, 1K, 10K, 100K, 1M, 10M, 100M.
var sizeBuckets = prometheus.ExponentialBuckets(100, 10, 7)

// NewWSMetrics creates a new WSMetrics instance with all metrics
// registered via promauto (default global registry).
func NewWSMetrics() *WSMetrics {
	return &WSMetrics{
		ConnectionsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "gateway",
				Subsystem: "ws",
				Name:      "connections_total",
				Help: "Total number of WebSocket " +
					"connections",
			},
			[]string{"route", "backend"},
		),
		ConnectionsActive: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "gateway",
				Subsystem: "ws",
				Name:      "connections_active",
				Help: "Number of active WebSocket " +
					"connections",
			},
			[]string{"route", "backend"},
		),
		MessagesSentTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "gateway",
				Subsystem: "ws",
				Name:      "messages_sent_total",
				Help: "Total number of WebSocket " +
					"messages sent",
			},
			[]string{"route", "backend"},
		),
		MessagesReceivedTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "gateway",
				Subsystem: "ws",
				Name:      "messages_received_total",
				Help: "Total number of WebSocket " +
					"messages received",
			},
			[]string{"route", "backend"},
		),
		ErrorsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "gateway",
				Subsystem: "ws",
				Name:      "errors_total",
				Help: "Total number of WebSocket " +
					"errors by type",
			},
			[]string{"route", "backend", "error_type"},
		),
		ConnectionDurationSeconds: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "gateway",
				Subsystem: "ws",
				Name:      "connection_duration_seconds",
				Help: "Duration of WebSocket " +
					"connections in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"route", "backend"},
		),
		MessageSizeBytes: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "gateway",
				Subsystem: "ws",
				Name:      "message_size_bytes",
				Help: "WebSocket message size " +
					"in bytes",
				Buckets: sizeBuckets,
			},
			[]string{"route", "backend", "direction"},
		),
	}
}

// GetWSMetrics returns the singleton WebSocket metrics instance.
func GetWSMetrics() *WSMetrics {
	wsMetricsOnce.Do(func() {
		wsMetricsInstance = NewWSMetrics()
	})
	return wsMetricsInstance
}

// MustRegister registers all WebSocket metric collectors with the
// given Prometheus registry. It uses Register (not MustRegister) to
// gracefully handle duplicate registration that can occur when
// providers are recreated on config reload.
// AlreadyRegisteredError is silently ignored.
func (m *WSMetrics) MustRegister(registry *prometheus.Registry) {
	for _, c := range m.collectors() {
		if err := registry.Register(c); err != nil {
			if !isAlreadyRegistered(err) {
				panic(err)
			}
		}
	}
}

// Init pre-initializes common label combinations with zero values so
// that metrics appear in /metrics output immediately after startup.
// Prometheus *Vec types only emit metric lines after
// WithLabelValues() is called at least once. This method is
// idempotent and safe to call multiple times.
func (m *WSMetrics) Init() {
	directions := []string{"sent", "received"}
	errorTypes := []string{
		"upgrade_failed", "connection_closed",
		"read_error", "write_error", "timeout",
	}

	rt := defaultLabel
	be := defaultLabel

	m.ConnectionsTotal.WithLabelValues(rt, be)
	m.ConnectionsActive.WithLabelValues(rt, be)
	m.MessagesSentTotal.WithLabelValues(rt, be)
	m.MessagesReceivedTotal.WithLabelValues(rt, be)
	m.ConnectionDurationSeconds.WithLabelValues(rt, be)

	for _, et := range errorTypes {
		m.ErrorsTotal.WithLabelValues(rt, be, et)
	}
	for _, dir := range directions {
		m.MessageSizeBytes.WithLabelValues(rt, be, dir)
	}
}

// RecordConnection records a new WebSocket connection.
func (m *WSMetrics) RecordConnection(route, backend string) {
	m.ConnectionsTotal.WithLabelValues(route, backend).Inc()
	m.ConnectionsActive.WithLabelValues(route, backend).Inc()
}

// RecordDisconnection records a WebSocket disconnection with its
// duration.
func (m *WSMetrics) RecordDisconnection(
	route, backend string, duration time.Duration,
) {
	m.ConnectionsActive.WithLabelValues(route, backend).Dec()
	m.ConnectionDurationSeconds.WithLabelValues(
		route, backend,
	).Observe(duration.Seconds())
}

// RecordMessageSent records a sent WebSocket message.
func (m *WSMetrics) RecordMessageSent(
	route, backend string, sizeBytes int64,
) {
	m.MessagesSentTotal.WithLabelValues(route, backend).Inc()
	m.MessageSizeBytes.WithLabelValues(
		route, backend, "sent",
	).Observe(float64(sizeBytes))
}

// RecordMessageReceived records a received WebSocket message.
func (m *WSMetrics) RecordMessageReceived(
	route, backend string, sizeBytes int64,
) {
	m.MessagesReceivedTotal.WithLabelValues(
		route, backend,
	).Inc()
	m.MessageSizeBytes.WithLabelValues(
		route, backend, "received",
	).Observe(float64(sizeBytes))
}

// RecordError records a WebSocket error by type.
func (m *WSMetrics) RecordError(
	route, backend, errorType string,
) {
	m.ErrorsTotal.WithLabelValues(
		route, backend, errorType,
	).Inc()
}

// collectors returns all WebSocket metric collectors for
// registration.
func (m *WSMetrics) collectors() []prometheus.Collector {
	return []prometheus.Collector{
		m.ConnectionsTotal,
		m.ConnectionsActive,
		m.MessagesSentTotal,
		m.MessagesReceivedTotal,
		m.ErrorsTotal,
		m.ConnectionDurationSeconds,
		m.MessageSizeBytes,
	}
}

// NewGRPCStreamMetrics creates a new GRPCStreamMetrics instance with
// all metrics registered via promauto (default global registry).
func NewGRPCStreamMetrics() *GRPCStreamMetrics {
	return &GRPCStreamMetrics{
		MessagesSentTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "gateway",
				Subsystem: "grpc_stream",
				Name:      "messages_sent_total",
				Help: "Total number of gRPC stream " +
					"messages sent",
			},
			[]string{"route", "method"},
		),
		MessagesReceivedTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "gateway",
				Subsystem: "grpc_stream",
				Name:      "messages_received_total",
				Help: "Total number of gRPC stream " +
					"messages received",
			},
			[]string{"route", "method"},
		),
		Active: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "gateway",
				Subsystem: "grpc_stream",
				Name:      "active",
				Help: "Number of active gRPC " +
					"streams",
			},
			[]string{"route", "method"},
		),
		DurationSeconds: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "gateway",
				Subsystem: "grpc_stream",
				Name:      "duration_seconds",
				Help: "Duration of gRPC streams " +
					"in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"route", "method"},
		),
		MessageSizeBytes: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "gateway",
				Subsystem: "grpc_stream",
				Name:      "message_size_bytes",
				Help: "gRPC stream message size " +
					"in bytes",
				Buckets: sizeBuckets,
			},
			[]string{"route", "method", "direction"},
		),
	}
}

// GetGRPCStreamMetrics returns the singleton gRPC stream metrics
// instance.
func GetGRPCStreamMetrics() *GRPCStreamMetrics {
	grpcMetricsOnce.Do(func() {
		grpcMetricsInstance = NewGRPCStreamMetrics()
	})
	return grpcMetricsInstance
}

// MustRegister registers all gRPC stream metric collectors with the
// given Prometheus registry. It uses Register (not MustRegister) to
// gracefully handle duplicate registration that can occur when
// providers are recreated on config reload.
// AlreadyRegisteredError is silently ignored.
func (m *GRPCStreamMetrics) MustRegister(
	registry *prometheus.Registry,
) {
	for _, c := range m.collectors() {
		if err := registry.Register(c); err != nil {
			if !isAlreadyRegistered(err) {
				panic(err)
			}
		}
	}
}

// Init pre-initializes common label combinations with zero values so
// that metrics appear in /metrics output immediately after startup.
// Prometheus *Vec types only emit metric lines after
// WithLabelValues() is called at least once. This method is
// idempotent and safe to call multiple times.
func (m *GRPCStreamMetrics) Init() {
	directions := []string{"sent", "received"}

	rt := defaultLabel
	method := defaultLabel

	m.MessagesSentTotal.WithLabelValues(rt, method)
	m.MessagesReceivedTotal.WithLabelValues(rt, method)
	m.Active.WithLabelValues(rt, method)
	m.DurationSeconds.WithLabelValues(rt, method)

	for _, dir := range directions {
		m.MessageSizeBytes.WithLabelValues(rt, method, dir)
	}
}

// RecordStreamStart records the start of a gRPC stream.
func (m *GRPCStreamMetrics) RecordStreamStart(
	route, method string,
) {
	m.Active.WithLabelValues(route, method).Inc()
}

// RecordStreamEnd records the end of a gRPC stream with its
// duration.
func (m *GRPCStreamMetrics) RecordStreamEnd(
	route, method string, duration time.Duration,
) {
	m.Active.WithLabelValues(route, method).Dec()
	m.DurationSeconds.WithLabelValues(route, method).Observe(
		duration.Seconds(),
	)
}

// RecordMessageSent records a sent gRPC stream message.
func (m *GRPCStreamMetrics) RecordMessageSent(
	route, method string, sizeBytes int64,
) {
	m.MessagesSentTotal.WithLabelValues(route, method).Inc()
	m.MessageSizeBytes.WithLabelValues(
		route, method, "sent",
	).Observe(float64(sizeBytes))
}

// RecordMessageReceived records a received gRPC stream message.
func (m *GRPCStreamMetrics) RecordMessageReceived(
	route, method string, sizeBytes int64,
) {
	m.MessagesReceivedTotal.WithLabelValues(route, method).Inc()
	m.MessageSizeBytes.WithLabelValues(
		route, method, "received",
	).Observe(float64(sizeBytes))
}

// collectors returns all gRPC stream metric collectors for
// registration.
func (m *GRPCStreamMetrics) collectors() []prometheus.Collector {
	return []prometheus.Collector{
		m.MessagesSentTotal,
		m.MessagesReceivedTotal,
		m.Active,
		m.DurationSeconds,
		m.MessageSizeBytes,
	}
}

// isAlreadyRegistered returns true if the error indicates the
// collector was already registered with the registry.
func isAlreadyRegistered(err error) bool {
	var are prometheus.AlreadyRegisteredError
	return errors.As(err, &are)
}
