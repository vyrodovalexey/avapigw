// Package proxy provides HTTP reverse proxy functionality.
package proxy

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// webSocketMetrics contains Prometheus metrics for WebSocket connections.
type webSocketMetrics struct {
	connectionsTotal  *prometheus.CounterVec
	connectionsActive *prometheus.GaugeVec
	errorsTotal       *prometheus.CounterVec
}

var (
	wsMetricsInstance *webSocketMetrics
	wsMetricsOnce     sync.Once
)

// getWebSocketMetrics returns the singleton WebSocket metrics instance.
func getWebSocketMetrics() *webSocketMetrics {
	wsMetricsOnce.Do(func() {
		wsMetricsInstance = &webSocketMetrics{
			connectionsTotal: promauto.NewCounterVec(
				prometheus.CounterOpts{
					Namespace: "avapigw",
					Name:      "websocket_connections_total",
					Help:      "Total number of WebSocket connections established",
				},
				[]string{"backend"},
			),
			connectionsActive: promauto.NewGaugeVec(
				prometheus.GaugeOpts{
					Namespace: "avapigw",
					Name:      "websocket_connections_active",
					Help:      "Number of currently active WebSocket connections",
				},
				[]string{"backend"},
			),
			errorsTotal: promauto.NewCounterVec(
				prometheus.CounterOpts{
					Namespace: "avapigw",
					Name:      "websocket_errors_total",
					Help:      "Total number of WebSocket errors",
				},
				[]string{"backend", "error_type"},
			),
		}
	})
	return wsMetricsInstance
}
