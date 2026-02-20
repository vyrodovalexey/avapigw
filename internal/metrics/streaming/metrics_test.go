package streaming

import (
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Package-level instances created once to avoid duplicate promauto
// registration panics. We use the singleton getters so that
// Get*Metrics() tests work correctly.
var (
	testWSMetrics     *WSMetrics
	testWSMetricsOnce sync.Once
	testWSReg         *prometheus.Registry

	testGRPCMetrics     *GRPCStreamMetrics
	testGRPCMetricsOnce sync.Once
	testGRPCReg         *prometheus.Registry
)

func getTestWSMetrics() (*WSMetrics, *prometheus.Registry) {
	testWSMetricsOnce.Do(func() {
		testWSMetrics = GetWSMetrics()
		testWSReg = prometheus.NewRegistry()
		testWSMetrics.MustRegister(testWSReg)
	})
	return testWSMetrics, testWSReg
}

func getTestGRPCStreamMetrics() (*GRPCStreamMetrics, *prometheus.Registry) {
	testGRPCMetricsOnce.Do(func() {
		testGRPCMetrics = GetGRPCStreamMetrics()
		testGRPCReg = prometheus.NewRegistry()
		testGRPCMetrics.MustRegister(testGRPCReg)
	})
	return testGRPCMetrics, testGRPCReg
}

// gatherAndFind gathers metrics from the registry and checks that
// the named metric family exists and has at least one metric.
func gatherAndFind(t *testing.T, reg *prometheus.Registry, name string) {
	t.Helper()
	mfs, err := reg.Gather()
	require.NoError(t, err)

	found := false
	for _, mf := range mfs {
		if mf.GetName() == name {
			found = true
			assert.NotEmpty(t, mf.GetMetric(),
				"%s should have at least one metric", name)
			break
		}
	}
	assert.True(t, found, "%s should be present in gathered metrics", name)
}

// ===================== WSMetrics Tests =====================

func TestNewWSMetrics(t *testing.T) {
	m, _ := getTestWSMetrics()
	require.NotNil(t, m)

	assert.NotNil(t, m.ConnectionsTotal)
	assert.NotNil(t, m.ConnectionsActive)
	assert.NotNil(t, m.MessagesSentTotal)
	assert.NotNil(t, m.MessagesReceivedTotal)
	assert.NotNil(t, m.ErrorsTotal)
	assert.NotNil(t, m.ConnectionDurationSeconds)
	assert.NotNil(t, m.MessageSizeBytes)
}

func TestGetWSMetrics_Singleton(t *testing.T) {
	m1 := GetWSMetrics()
	m2 := GetWSMetrics()

	require.NotNil(t, m1)
	assert.Same(t, m1, m2, "should return same instance")
}

// --- Registration ---

func TestWSMetrics_MustRegister(t *testing.T) {
	m, reg := getTestWSMetrics()

	m.ConnectionsTotal.WithLabelValues("reg-r", "reg-b").Inc()
	mfs, err := reg.Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, mfs, "registry should contain metrics after registration")
}

func TestWSMetrics_MustRegister_Duplicate(t *testing.T) {
	m, reg := getTestWSMetrics()

	assert.NotPanics(t, func() {
		m.MustRegister(reg)
	})
}

// --- Init ---

func TestWSMetrics_Init(t *testing.T) {
	m, reg := getTestWSMetrics()

	assert.NotPanics(t, func() {
		m.Init()
	})

	mfs, err := reg.Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, mfs, "Init should pre-populate metrics")

	names := make(map[string]bool)
	for _, mf := range mfs {
		names[mf.GetName()] = true
	}
	assert.True(t, names["gateway_ws_connections_total"])
	assert.True(t, names["gateway_ws_connections_active"])
	assert.True(t, names["gateway_ws_messages_sent_total"])
	assert.True(t, names["gateway_ws_messages_received_total"])
	assert.True(t, names["gateway_ws_errors_total"])
	assert.True(t, names["gateway_ws_message_size_bytes"])
}

// --- Record helpers ---

func TestWSMetrics_RecordConnection(t *testing.T) {
	m, reg := getTestWSMetrics()

	beforeConn := testutil.ToFloat64(
		m.ConnectionsTotal.WithLabelValues("ws-conn-rt", "ws-conn-be"),
	)
	beforeActive := testutil.ToFloat64(
		m.ConnectionsActive.WithLabelValues("ws-conn-rt", "ws-conn-be"),
	)

	m.RecordConnection("ws-conn-rt", "ws-conn-be")

	gatherAndFind(t, reg, "gateway_ws_connections_total")
	gatherAndFind(t, reg, "gateway_ws_connections_active")

	afterConn := testutil.ToFloat64(
		m.ConnectionsTotal.WithLabelValues("ws-conn-rt", "ws-conn-be"),
	)
	assert.Equal(t, beforeConn+1, afterConn)

	afterActive := testutil.ToFloat64(
		m.ConnectionsActive.WithLabelValues("ws-conn-rt", "ws-conn-be"),
	)
	assert.Equal(t, beforeActive+1, afterActive)
}

func TestWSMetrics_RecordDisconnection(t *testing.T) {
	m, reg := getTestWSMetrics()

	// Connect first, then disconnect.
	m.RecordConnection("ws-disc-rt", "ws-disc-be")
	m.RecordDisconnection("ws-disc-rt", "ws-disc-be", 5*time.Second)

	gatherAndFind(t, reg, "gateway_ws_connection_duration_seconds")

	active := testutil.ToFloat64(
		m.ConnectionsActive.WithLabelValues("ws-disc-rt", "ws-disc-be"),
	)
	assert.Equal(t, float64(0), active,
		"active connections should be 0 after disconnect")
}

func TestWSMetrics_RecordMessageSent(t *testing.T) {
	m, reg := getTestWSMetrics()

	before := testutil.ToFloat64(
		m.MessagesSentTotal.WithLabelValues("ws-sent-rt", "ws-sent-be"),
	)

	m.RecordMessageSent("ws-sent-rt", "ws-sent-be", 512)

	gatherAndFind(t, reg, "gateway_ws_messages_sent_total")
	gatherAndFind(t, reg, "gateway_ws_message_size_bytes")

	after := testutil.ToFloat64(
		m.MessagesSentTotal.WithLabelValues("ws-sent-rt", "ws-sent-be"),
	)
	assert.Equal(t, before+1, after)
}

func TestWSMetrics_RecordMessageReceived(t *testing.T) {
	m, reg := getTestWSMetrics()

	before := testutil.ToFloat64(
		m.MessagesReceivedTotal.WithLabelValues("ws-recv-rt", "ws-recv-be"),
	)

	m.RecordMessageReceived("ws-recv-rt", "ws-recv-be", 1024)

	gatherAndFind(t, reg, "gateway_ws_messages_received_total")
	gatherAndFind(t, reg, "gateway_ws_message_size_bytes")

	after := testutil.ToFloat64(
		m.MessagesReceivedTotal.WithLabelValues("ws-recv-rt", "ws-recv-be"),
	)
	assert.Equal(t, before+1, after)
}

func TestWSMetrics_RecordError(t *testing.T) {
	m, reg := getTestWSMetrics()

	before := testutil.ToFloat64(
		m.ErrorsTotal.WithLabelValues("ws-err-rt", "ws-err-be", "read_error"),
	)

	m.RecordError("ws-err-rt", "ws-err-be", "read_error")

	gatherAndFind(t, reg, "gateway_ws_errors_total")

	after := testutil.ToFloat64(
		m.ErrorsTotal.WithLabelValues("ws-err-rt", "ws-err-be", "read_error"),
	)
	assert.Equal(t, before+1, after)
}

// --- WS collectors ---

func TestWSMetrics_Collectors(t *testing.T) {
	m, _ := getTestWSMetrics()
	collectors := m.collectors()

	// 7 metric fields.
	assert.Len(t, collectors, 7, "should return 7 collectors")

	for i, c := range collectors {
		assert.NotNil(t, c, "collector %d should not be nil", i)
	}
}

// --- WS Concurrent access ---

func TestWSMetrics_ConcurrentAccess(t *testing.T) {
	m, _ := getTestWSMetrics()

	const goroutines = 10
	const iterations = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				m.RecordConnection("concurrent", "be")
				m.RecordMessageSent("concurrent", "be", 100)
				m.RecordMessageReceived("concurrent", "be", 200)
				m.RecordError("concurrent", "be", "timeout")
				m.RecordDisconnection("concurrent", "be", time.Second)
			}
		}()
	}

	wg.Wait()
}

// ===================== GRPCStreamMetrics Tests =====================

func TestNewGRPCStreamMetrics(t *testing.T) {
	m, _ := getTestGRPCStreamMetrics()
	require.NotNil(t, m)

	assert.NotNil(t, m.MessagesSentTotal)
	assert.NotNil(t, m.MessagesReceivedTotal)
	assert.NotNil(t, m.Active)
	assert.NotNil(t, m.DurationSeconds)
	assert.NotNil(t, m.MessageSizeBytes)
}

func TestGetGRPCStreamMetrics_Singleton(t *testing.T) {
	m1 := GetGRPCStreamMetrics()
	m2 := GetGRPCStreamMetrics()

	require.NotNil(t, m1)
	assert.Same(t, m1, m2, "should return same instance")
}

// --- Registration ---

func TestGRPCStreamMetrics_MustRegister(t *testing.T) {
	m, reg := getTestGRPCStreamMetrics()

	m.MessagesSentTotal.WithLabelValues("reg-r", "reg-m").Inc()
	mfs, err := reg.Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, mfs, "registry should contain metrics after registration")
}

func TestGRPCStreamMetrics_MustRegister_Duplicate(t *testing.T) {
	m, reg := getTestGRPCStreamMetrics()

	assert.NotPanics(t, func() {
		m.MustRegister(reg)
	})
}

// --- Init ---

func TestGRPCStreamMetrics_Init(t *testing.T) {
	m, reg := getTestGRPCStreamMetrics()

	assert.NotPanics(t, func() {
		m.Init()
	})

	mfs, err := reg.Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, mfs, "Init should pre-populate metrics")

	names := make(map[string]bool)
	for _, mf := range mfs {
		names[mf.GetName()] = true
	}
	assert.True(t, names["gateway_grpc_stream_messages_sent_total"])
	assert.True(t, names["gateway_grpc_stream_messages_received_total"])
	assert.True(t, names["gateway_grpc_stream_active"])
	assert.True(t, names["gateway_grpc_stream_message_size_bytes"])
}

// --- Record helpers ---

func TestGRPCStreamMetrics_RecordStreamStart(t *testing.T) {
	m, reg := getTestGRPCStreamMetrics()

	before := testutil.ToFloat64(
		m.Active.WithLabelValues("grpc-start-rt", "TestMethod"),
	)

	m.RecordStreamStart("grpc-start-rt", "TestMethod")

	gatherAndFind(t, reg, "gateway_grpc_stream_active")

	after := testutil.ToFloat64(
		m.Active.WithLabelValues("grpc-start-rt", "TestMethod"),
	)
	assert.Equal(t, before+1, after)
}

func TestGRPCStreamMetrics_RecordStreamEnd(t *testing.T) {
	m, reg := getTestGRPCStreamMetrics()

	// Start then end.
	m.RecordStreamStart("grpc-end-rt", "EndMethod")
	m.RecordStreamEnd("grpc-end-rt", "EndMethod", 10*time.Second)

	gatherAndFind(t, reg, "gateway_grpc_stream_duration_seconds")

	val := testutil.ToFloat64(
		m.Active.WithLabelValues("grpc-end-rt", "EndMethod"),
	)
	assert.Equal(t, float64(0), val,
		"active streams should be 0 after end")
}

func TestGRPCStreamMetrics_RecordMessageSent(t *testing.T) {
	m, reg := getTestGRPCStreamMetrics()

	before := testutil.ToFloat64(
		m.MessagesSentTotal.WithLabelValues("grpc-sent-rt", "SentMethod"),
	)

	m.RecordMessageSent("grpc-sent-rt", "SentMethod", 256)

	gatherAndFind(t, reg, "gateway_grpc_stream_messages_sent_total")
	gatherAndFind(t, reg, "gateway_grpc_stream_message_size_bytes")

	after := testutil.ToFloat64(
		m.MessagesSentTotal.WithLabelValues("grpc-sent-rt", "SentMethod"),
	)
	assert.Equal(t, before+1, after)
}

func TestGRPCStreamMetrics_RecordMessageReceived(t *testing.T) {
	m, reg := getTestGRPCStreamMetrics()

	before := testutil.ToFloat64(
		m.MessagesReceivedTotal.WithLabelValues("grpc-recv-rt", "RecvMethod"),
	)

	m.RecordMessageReceived("grpc-recv-rt", "RecvMethod", 512)

	gatherAndFind(t, reg, "gateway_grpc_stream_messages_received_total")
	gatherAndFind(t, reg, "gateway_grpc_stream_message_size_bytes")

	after := testutil.ToFloat64(
		m.MessagesReceivedTotal.WithLabelValues("grpc-recv-rt", "RecvMethod"),
	)
	assert.Equal(t, before+1, after)
}

// --- gRPC collectors ---

func TestGRPCStreamMetrics_Collectors(t *testing.T) {
	m, _ := getTestGRPCStreamMetrics()
	collectors := m.collectors()

	// 5 metric fields.
	assert.Len(t, collectors, 5, "should return 5 collectors")

	for i, c := range collectors {
		assert.NotNil(t, c, "collector %d should not be nil", i)
	}
}

// --- gRPC Concurrent access ---

func TestGRPCStreamMetrics_ConcurrentAccess(t *testing.T) {
	m, _ := getTestGRPCStreamMetrics()

	const goroutines = 10
	const iterations = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				m.RecordStreamStart("concurrent", "Method")
				m.RecordMessageSent("concurrent", "Method", 100)
				m.RecordMessageReceived("concurrent", "Method", 200)
				m.RecordStreamEnd("concurrent", "Method", time.Second)
			}
		}()
	}

	wg.Wait()
}

// --- isAlreadyRegistered ---

func TestIsAlreadyRegistered(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name: "AlreadyRegisteredError",
			err: prometheus.AlreadyRegisteredError{
				ExistingCollector: nil,
				NewCollector:      nil,
			},
			expected: true,
		},
		{
			name:     "other error",
			err:      assert.AnError,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isAlreadyRegistered(tt.err))
		})
	}
}

// --- Table-driven WS RecordError ---

func TestWSMetrics_RecordError_TableDriven(t *testing.T) {
	tests := []struct {
		name      string
		route     string
		backend   string
		errorType string
	}{
		{
			name:      "upgrade_failed",
			route:     "td-ws-route",
			backend:   "td-ws-be",
			errorType: "upgrade_failed",
		},
		{
			name:      "connection_closed",
			route:     "td-ws-route",
			backend:   "td-ws-be",
			errorType: "connection_closed",
		},
		{
			name:      "read_error",
			route:     "td-ws-route",
			backend:   "td-ws-be",
			errorType: "read_error",
		},
		{
			name:      "write_error",
			route:     "td-ws-route",
			backend:   "td-ws-be",
			errorType: "write_error",
		},
		{
			name:      "timeout",
			route:     "td-ws-route",
			backend:   "td-ws-be",
			errorType: "timeout",
		},
	}

	m, reg := getTestWSMetrics()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m.RecordError(tt.route, tt.backend, tt.errorType)

			gatherAndFind(t, reg, "gateway_ws_errors_total")
		})
	}
}

// --- Table-driven gRPC RecordMessageSent ---

func TestGRPCStreamMetrics_RecordMessageSent_TableDriven(t *testing.T) {
	tests := []struct {
		name      string
		route     string
		method    string
		sizeBytes int64
	}{
		{
			name:      "small message",
			route:     "td-grpc-route",
			method:    "GetUser",
			sizeBytes: 64,
		},
		{
			name:      "medium message",
			route:     "td-grpc-route",
			method:    "ListUsers",
			sizeBytes: 4096,
		},
		{
			name:      "large message",
			route:     "td-grpc-route",
			method:    "BulkExport",
			sizeBytes: 1048576,
		},
		{
			name:      "zero size",
			route:     "td-grpc-route",
			method:    "Ping",
			sizeBytes: 0,
		},
	}

	m, reg := getTestGRPCStreamMetrics()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m.RecordMessageSent(tt.route, tt.method, tt.sizeBytes)

			gatherAndFind(t, reg, "gateway_grpc_stream_messages_sent_total")
			gatherAndFind(t, reg, "gateway_grpc_stream_message_size_bytes")
		})
	}
}
