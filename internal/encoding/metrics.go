// Package encoding provides encoding/decoding capabilities for the API Gateway.
package encoding

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// EncodingMetrics contains Prometheus metrics for encoding operations.
type EncodingMetrics struct {
	negotiationsTotal *prometheus.CounterVec
	encodeTotal       *prometheus.CounterVec
	decodeTotal       *prometheus.CounterVec
	errorsTotal       *prometheus.CounterVec
}

var (
	encodingMetricsInstance *EncodingMetrics
	encodingMetricsOnce     sync.Once
)

// GetEncodingMetrics returns the singleton encoding metrics instance.
func GetEncodingMetrics() *EncodingMetrics {
	encodingMetricsOnce.Do(func() {
		encodingMetricsInstance = &EncodingMetrics{
			negotiationsTotal: promauto.NewCounterVec(
				prometheus.CounterOpts{
					Namespace: "gateway",
					Subsystem: "encoding",
					Name:      "negotiations_total",
					Help:      "Total number of content type negotiations",
				},
				[]string{"content_type", "result"},
			),
			encodeTotal: promauto.NewCounterVec(
				prometheus.CounterOpts{
					Namespace: "gateway",
					Subsystem: "encoding",
					Name:      "encode_total",
					Help:      "Total number of encode operations",
				},
				[]string{"content_type", "result"},
			),
			decodeTotal: promauto.NewCounterVec(
				prometheus.CounterOpts{
					Namespace: "gateway",
					Subsystem: "encoding",
					Name:      "decode_total",
					Help:      "Total number of decode operations",
				},
				[]string{"content_type", "result"},
			),
			errorsTotal: promauto.NewCounterVec(
				prometheus.CounterOpts{
					Namespace: "gateway",
					Subsystem: "encoding",
					Name:      "errors_total",
					Help:      "Total number of encoding/decoding errors",
				},
				[]string{"content_type", "operation"},
			),
		}
	})
	return encodingMetricsInstance
}

// MustRegister registers all encoding metric collectors with the given
// Prometheus registry. This is needed because promauto registers
// metrics with the default global registry, but the gateway serves
// /metrics from a custom registry. Calling MustRegister bridges the
// two so encoding metrics appear on the gateway's metrics endpoint.
func (m *EncodingMetrics) MustRegister(registry *prometheus.Registry) {
	registry.MustRegister(
		m.negotiationsTotal,
		m.encodeTotal,
		m.decodeTotal,
		m.errorsTotal,
	)
}

// Init pre-initializes common label combinations with zero values so that
// metrics appear in /metrics output immediately after startup. Prometheus
// *Vec types only emit metric lines after WithLabelValues() is called at
// least once. This method is idempotent and safe to call multiple times.
func (m *EncodingMetrics) Init() {
	for _, ct := range []string{"application/json", "application/xml", "application/yaml"} {
		for _, result := range []string{"success", "error"} {
			m.negotiationsTotal.WithLabelValues(ct, result)
			m.encodeTotal.WithLabelValues(ct, result)
			m.decodeTotal.WithLabelValues(ct, result)
		}
		for _, op := range []string{"encode", "decode"} {
			m.errorsTotal.WithLabelValues(ct, op)
		}
	}
}

// RecordNegotiation records a content type negotiation result.
func (m *EncodingMetrics) RecordNegotiation(contentType, result string) {
	m.negotiationsTotal.WithLabelValues(contentType, result).Inc()
}

// RecordEncode records an encode operation.
func (m *EncodingMetrics) RecordEncode(contentType, result string) {
	m.encodeTotal.WithLabelValues(contentType, result).Inc()
}

// RecordDecode records a decode operation.
func (m *EncodingMetrics) RecordDecode(contentType, result string) {
	m.decodeTotal.WithLabelValues(contentType, result).Inc()
}

// RecordError records an encoding/decoding error.
func (m *EncodingMetrics) RecordError(contentType, operation string) {
	m.errorsTotal.WithLabelValues(contentType, operation).Inc()
}
