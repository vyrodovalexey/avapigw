// Package proxy provides HTTP reverse proxy functionality.
package proxy

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// webSocketMetrics contains Prometheus metrics for WebSocket connections.
type webSocketMetrics struct {
	connectionsTotal      *prometheus.CounterVec
	connectionsActive     *prometheus.GaugeVec
	errorsTotal           *prometheus.CounterVec
	messagesSentTotal     *prometheus.CounterVec
	messagesReceivedTotal *prometheus.CounterVec
	connectionDuration    *prometheus.HistogramVec
}

var (
	wsMetricsInstance *webSocketMetrics
	wsMetricsOnce     sync.Once
)

// initWebSocketMetrics initializes the singleton WebSocket metrics
// instance with the given Prometheus registry. If registry is nil,
// metrics are registered with the default registerer. Must be called
// before getWebSocketMetrics; subsequent calls are no-ops (sync.Once).
func initWebSocketMetrics(registry *prometheus.Registry) {
	wsMetricsOnce.Do(func() {
		var registerer prometheus.Registerer
		if registry != nil {
			registerer = registry
		} else {
			registerer = prometheus.DefaultRegisterer
		}
		factory := promauto.With(registerer)
		wsMetricsInstance = &webSocketMetrics{
			connectionsTotal: factory.NewCounterVec(
				prometheus.CounterOpts{
					Namespace: "gateway",
					Name:      "websocket_connections_total",
					Help:      "Total number of WebSocket connections established",
				},
				[]string{"backend"},
			),
			connectionsActive: factory.NewGaugeVec(
				prometheus.GaugeOpts{
					Namespace: "gateway",
					Name:      "websocket_connections_active",
					Help:      "Number of currently active WebSocket connections",
				},
				[]string{"backend"},
			),
			errorsTotal: factory.NewCounterVec(
				prometheus.CounterOpts{
					Namespace: "gateway",
					Name:      "websocket_errors_total",
					Help:      "Total number of WebSocket errors",
				},
				[]string{"backend", "error_type"},
			),
			messagesSentTotal: factory.NewCounterVec(
				prometheus.CounterOpts{
					Namespace: "gateway",
					Name:      "websocket_messages_sent_total",
					Help:      "Total number of WebSocket messages sent to clients",
				},
				[]string{"backend"},
			),
			messagesReceivedTotal: factory.NewCounterVec(
				prometheus.CounterOpts{
					Namespace: "gateway",
					Name:      "websocket_messages_received_total",
					Help:      "Total number of WebSocket messages received from clients",
				},
				[]string{"backend"},
			),
			connectionDuration: factory.NewHistogramVec(
				prometheus.HistogramOpts{
					Namespace: "gateway",
					Name:      "websocket_connection_duration_seconds",
					Help:      "Duration of WebSocket connections in seconds",
					Buckets:   []float64{1, 5, 10, 30, 60, 120, 300, 600, 1800, 3600},
				},
				[]string{"backend"},
			),
		}
	})
}

// initWebSocketVecMetrics pre-populates common label combinations
// with zero values so that WebSocket Vec metrics appear in /metrics
// output immediately after startup. Must be called after
// initWebSocketMetrics.
func initWebSocketVecMetrics() {
	m := getWebSocketMetrics()

	errorTypes := []string{
		"upgrade_failed",
		"connection_closed",
		"read_error",
		"write_error",
	}
	for _, et := range errorTypes {
		m.errorsTotal.WithLabelValues("default", et)
	}

	m.messagesReceivedTotal.WithLabelValues("default")
}

// getWebSocketMetrics returns the singleton WebSocket metrics instance.
// If initWebSocketMetrics has not been called, metrics are lazily
// initialized with the default registerer.
func getWebSocketMetrics() *webSocketMetrics {
	initWebSocketMetrics(nil)
	return wsMetricsInstance
}
