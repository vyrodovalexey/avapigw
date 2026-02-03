// Copyright 2026 The avapigw Authors.
// SPDX-License-Identifier: Apache-2.0

package operator

import (
	"github.com/prometheus/client_golang/prometheus"
)

const (
	// metricsNamespace is the namespace for operator client metrics.
	metricsNamespace = "avapigw"
	// metricsSubsystem is the subsystem for operator client metrics.
	metricsSubsystem = "gateway_operator"
)

// clientMetrics holds Prometheus metrics for the operator client.
type clientMetrics struct {
	connected           prometheus.Gauge
	reconnectsTotal     prometheus.Counter
	configUpdatesTotal  *prometheus.CounterVec
	configApplyDuration prometheus.Histogram
	heartbeatLatency    prometheus.Histogram
	streamErrors        prometheus.Counter
	registrationErrors  prometheus.Counter
	lastConfigVersion   prometheus.Gauge
	lastConfigTimestamp prometheus.Gauge
}

// newClientMetrics creates a new clientMetrics instance.
func newClientMetrics(registry prometheus.Registerer) *clientMetrics {
	m := &clientMetrics{
		connected: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystem,
			Name:      "connected",
			Help:      "Whether the gateway is connected to the operator (1=connected, 0=disconnected)",
		}),
		reconnectsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystem,
			Name:      "reconnects_total",
			Help:      "Total number of reconnection attempts to the operator",
		}),
		configUpdatesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystem,
			Name:      "config_updates_total",
			Help:      "Total number of configuration updates received from the operator",
		}, []string{"type", "status"}),
		configApplyDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystem,
			Name:      "config_apply_duration_seconds",
			Help:      "Time taken to apply configuration updates",
			Buckets:   []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
		}),
		heartbeatLatency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystem,
			Name:      "heartbeat_latency_seconds",
			Help:      "Latency of heartbeat requests to the operator",
			Buckets:   []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5},
		}),
		streamErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystem,
			Name:      "stream_errors_total",
			Help:      "Total number of stream errors encountered",
		}),
		registrationErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystem,
			Name:      "registration_errors_total",
			Help:      "Total number of registration errors encountered",
		}),
		lastConfigVersion: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystem,
			Name:      "last_config_version",
			Help:      "Sequence number of the last applied configuration",
		}),
		lastConfigTimestamp: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystem,
			Name:      "last_config_timestamp_seconds",
			Help:      "Unix timestamp of the last applied configuration",
		}),
	}

	if registry != nil {
		registry.MustRegister(
			m.connected,
			m.reconnectsTotal,
			m.configUpdatesTotal,
			m.configApplyDuration,
			m.heartbeatLatency,
			m.streamErrors,
			m.registrationErrors,
			m.lastConfigVersion,
			m.lastConfigTimestamp,
		)
	}

	return m
}

// setConnected sets the connection status metric.
func (m *clientMetrics) setConnected(connected bool) {
	if m == nil {
		return
	}
	if connected {
		m.connected.Set(1)
	} else {
		m.connected.Set(0)
	}
}

// incReconnects increments the reconnection counter.
func (m *clientMetrics) incReconnects() {
	if m == nil {
		return
	}
	m.reconnectsTotal.Inc()
}

// incConfigUpdates increments the config updates counter.
func (m *clientMetrics) incConfigUpdates(updateType, status string) {
	if m == nil {
		return
	}
	m.configUpdatesTotal.WithLabelValues(updateType, status).Inc()
}

// observeConfigApplyDuration records the config apply duration.
func (m *clientMetrics) observeConfigApplyDuration(seconds float64) {
	if m == nil {
		return
	}
	m.configApplyDuration.Observe(seconds)
}

// observeHeartbeatLatency records the heartbeat latency.
func (m *clientMetrics) observeHeartbeatLatency(seconds float64) {
	if m == nil {
		return
	}
	m.heartbeatLatency.Observe(seconds)
}

// incStreamErrors increments the stream errors counter.
func (m *clientMetrics) incStreamErrors() {
	if m == nil {
		return
	}
	m.streamErrors.Inc()
}

// incRegistrationErrors increments the registration errors counter.
func (m *clientMetrics) incRegistrationErrors() {
	if m == nil {
		return
	}
	m.registrationErrors.Inc()
}

// setLastConfigVersion sets the last config version metric.
func (m *clientMetrics) setLastConfigVersion(sequence int64) {
	if m == nil {
		return
	}
	m.lastConfigVersion.Set(float64(sequence))
}

// setLastConfigTimestamp sets the last config timestamp metric.
func (m *clientMetrics) setLastConfigTimestamp(timestamp float64) {
	if m == nil {
		return
	}
	m.lastConfigTimestamp.Set(timestamp)
}
