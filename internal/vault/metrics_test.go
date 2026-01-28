package vault

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func TestNewMetrics(t *testing.T) {
	tests := []struct {
		name              string
		namespace         string
		expectedNamespace string
	}{
		{
			name:              "default namespace when empty",
			namespace:         "",
			expectedNamespace: "gateway",
		},
		{
			name:              "custom namespace",
			namespace:         "custom",
			expectedNamespace: "custom",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMetrics(tt.namespace)
			if m == nil {
				t.Fatal("NewMetrics() returned nil")
			}
			if m.requestsTotal == nil {
				t.Error("requestsTotal should not be nil")
			}
			if m.requestDuration == nil {
				t.Error("requestDuration should not be nil")
			}
			if m.tokenTTL == nil {
				t.Error("tokenTTL should not be nil")
			}
			if m.cacheHits == nil {
				t.Error("cacheHits should not be nil")
			}
			if m.cacheMisses == nil {
				t.Error("cacheMisses should not be nil")
			}
			if m.authAttempts == nil {
				t.Error("authAttempts should not be nil")
			}
			if m.errors == nil {
				t.Error("errors should not be nil")
			}
			if m.registry == nil {
				t.Error("registry should not be nil")
			}
		})
	}
}

func TestNewMetrics_WithRegistry(t *testing.T) {
	customRegistry := prometheus.NewRegistry()
	m := NewMetrics("test", WithMetricsRegistry(customRegistry))

	if m.registry != customRegistry {
		t.Error("registry should be the custom registry")
	}
}

func TestMetrics_RecordRequest(t *testing.T) {
	m := NewMetrics("test")

	// Should not panic
	m.RecordRequest("read", "success", 100*time.Millisecond)
	m.RecordRequest("write", "error", 200*time.Millisecond)
	m.RecordRequest("authenticate", "success", 50*time.Millisecond)
}

func TestMetrics_SetTokenTTL(t *testing.T) {
	m := NewMetrics("test")

	// Should not panic
	m.SetTokenTTL(3600)
	m.SetTokenTTL(0)
	m.SetTokenTTL(-1)
}

func TestMetrics_RecordCacheHit(t *testing.T) {
	m := NewMetrics("test")

	// Should not panic
	m.RecordCacheHit()
	m.RecordCacheHit()
}

func TestMetrics_RecordCacheMiss(t *testing.T) {
	m := NewMetrics("test")

	// Should not panic
	m.RecordCacheMiss()
	m.RecordCacheMiss()
}

func TestMetrics_RecordAuthAttempt(t *testing.T) {
	m := NewMetrics("test")

	// Should not panic
	m.RecordAuthAttempt("token", "success")
	m.RecordAuthAttempt("kubernetes", "error")
	m.RecordAuthAttempt("approle", "success")
}

func TestMetrics_RecordError(t *testing.T) {
	m := NewMetrics("test")

	// Should not panic
	m.RecordError("authentication")
	m.RecordError("connection")
	m.RecordError("timeout")
}

func TestMetrics_Registry(t *testing.T) {
	m := NewMetrics("test")

	registry := m.Registry()
	if registry == nil {
		t.Error("Registry() should not return nil")
	}
}

func TestMetrics_Describe(t *testing.T) {
	m := NewMetrics("test")

	ch := make(chan *prometheus.Desc, 100)
	m.Describe(ch)
	close(ch)

	count := 0
	for range ch {
		count++
	}

	if count == 0 {
		t.Error("Describe() should send metric descriptions")
	}
}

func TestMetrics_Collect(t *testing.T) {
	m := NewMetrics("test")

	// Record some metrics first
	m.RecordRequest("read", "success", 100*time.Millisecond)
	m.RecordCacheHit()
	m.SetTokenTTL(3600)

	ch := make(chan prometheus.Metric, 100)
	m.Collect(ch)
	close(ch)

	count := 0
	for range ch {
		count++
	}

	if count == 0 {
		t.Error("Collect() should send metrics")
	}
}

func TestNopMetrics(t *testing.T) {
	m := NewNopMetrics()

	if m == nil {
		t.Fatal("NewNopMetrics() returned nil")
	}

	// All methods should not panic
	m.RecordRequest("read", "success", 100*time.Millisecond)
	m.SetTokenTTL(3600)
	m.RecordCacheHit()
	m.RecordCacheMiss()
	m.RecordAuthAttempt("token", "success")
	m.RecordError("test")
}

func TestMetricsRecorder_Interface(t *testing.T) {
	// Verify both implementations satisfy the interface
	var _ MetricsRecorder = (*Metrics)(nil)
	var _ MetricsRecorder = (*NopMetrics)(nil)
}

func TestWithMetricsRegistry(t *testing.T) {
	registry := prometheus.NewRegistry()
	opt := WithMetricsRegistry(registry)

	m := &Metrics{}
	opt(m)

	if m.registry != registry {
		t.Error("WithMetricsRegistry should set the registry")
	}
}

func TestMetrics_ConcurrentAccess(t *testing.T) {
	m := NewMetrics("test")

	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			m.RecordRequest("read", "success", time.Duration(i)*time.Millisecond)
		}
		close(done)
	}()

	go func() {
		for i := 0; i < 100; i++ {
			m.RecordCacheHit()
			m.RecordCacheMiss()
		}
	}()

	go func() {
		for i := 0; i < 100; i++ {
			m.SetTokenTTL(float64(i))
		}
	}()

	go func() {
		for i := 0; i < 100; i++ {
			m.RecordAuthAttempt("token", "success")
		}
	}()

	go func() {
		for i := 0; i < 100; i++ {
			m.RecordError("test")
		}
	}()

	<-done
	// Test passes if no race conditions occur
}

func TestMetrics_AllOperations(t *testing.T) {
	m := NewMetrics("gateway")

	operations := []string{"read", "write", "delete", "list", "authenticate", "renew_token", "health"}
	statuses := []string{"success", "error"}

	for _, op := range operations {
		for _, status := range statuses {
			m.RecordRequest(op, status, 100*time.Millisecond)
		}
	}

	// Verify metrics were recorded by collecting them
	ch := make(chan prometheus.Metric, 100)
	m.Collect(ch)
	close(ch)

	count := 0
	for range ch {
		count++
	}

	if count == 0 {
		t.Error("Should have collected metrics")
	}
}

func TestMetrics_AuthMethods(t *testing.T) {
	m := NewMetrics("gateway")

	methods := []string{"token", "kubernetes", "approle"}
	statuses := []string{"success", "error"}

	for _, method := range methods {
		for _, status := range statuses {
			m.RecordAuthAttempt(method, status)
		}
	}

	// Verify metrics were recorded
	ch := make(chan prometheus.Metric, 100)
	m.Collect(ch)
	close(ch)

	count := 0
	for range ch {
		count++
	}

	if count == 0 {
		t.Error("Should have collected auth attempt metrics")
	}
}

func TestMetrics_ErrorTypes(t *testing.T) {
	m := NewMetrics("gateway")

	errorTypes := []string{
		"authentication",
		"authorization",
		"connection",
		"timeout",
		"configuration",
		"secret_not_found",
	}

	for _, errType := range errorTypes {
		m.RecordError(errType)
	}

	// Verify metrics were recorded
	ch := make(chan prometheus.Metric, 100)
	m.Collect(ch)
	close(ch)

	count := 0
	for range ch {
		count++
	}

	if count == 0 {
		t.Error("Should have collected error metrics")
	}
}
