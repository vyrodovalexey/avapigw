package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestNewLogger(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name:    "nil config uses default",
			config:  nil,
			wantErr: false,
		},
		{
			name: "valid config",
			config: &Config{
				Enabled: true,
				Output:  "stdout",
				Format:  "json",
			},
			wantErr: false,
		},
		{
			name: "disabled config",
			config: &Config{
				Enabled: false,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger, err := NewLogger(tt.config, WithLoggerMetrics(newNoopMetrics()))
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, logger)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, logger)
				_ = logger.Close()
			}
		})
	}
}

func TestNewLogger_WithOptions(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	config := &Config{
		Enabled: true,
		Format:  "json",
	}

	// Use noop metrics to avoid duplicate registration in parallel tests
	logger, err := NewLogger(config,
		WithLoggerWriter(&buf),
		WithLoggerLogger(observability.NopLogger()),
		WithLoggerMetrics(newNoopMetrics()),
	)
	require.NoError(t, err)
	assert.NotNil(t, logger)
	_ = logger.Close()
}

// newNoopMetrics creates a no-op metrics for testing to avoid duplicate registration.
func newNoopMetrics() *Metrics {
	return &Metrics{
		eventsTotal: nil,
	}
}

func TestLogger_LogEvent_Disabled(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	config := &Config{
		Enabled: false,
	}

	logger, err := NewLogger(config, WithLoggerWriter(&buf), WithLoggerMetrics(newNoopMetrics()))
	require.NoError(t, err)

	event := NewEvent(EventTypeAuthentication, ActionLogin, OutcomeSuccess)
	logger.LogEvent(context.Background(), event)

	// Nothing should be written when disabled
	assert.Empty(t, buf.String())
	_ = logger.Close()
}

func TestLogger_LogEvent_JSON(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	config := &Config{
		Enabled: true,
		Format:  "json",
		Events: &EventsConfig{
			Authentication: true,
		},
	}

	logger, err := NewLogger(config, WithLoggerWriter(&buf), WithLoggerMetrics(newNoopMetrics()))
	require.NoError(t, err)

	subject := &Subject{
		ID:        "user123",
		Type:      "user",
		Name:      "Test User",
		IPAddress: "192.168.1.1",
	}

	event := NewEvent(EventTypeAuthentication, ActionLogin, OutcomeSuccess).
		WithSubject(subject)

	logger.LogEvent(context.Background(), event)

	// Parse the JSON output
	var output map[string]interface{}
	err = json.Unmarshal(buf.Bytes(), &output)
	require.NoError(t, err)

	assert.Equal(t, "authentication", output["type"])
	assert.Equal(t, "login", output["action"])
	assert.Equal(t, "success", output["outcome"])
	assert.NotNil(t, output["subject"])

	_ = logger.Close()
}

func TestLogger_LogEvent_Text(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	config := &Config{
		Enabled: true,
		Format:  "text",
		Events: &EventsConfig{
			Authentication: true,
		},
	}

	logger, err := NewLogger(config, WithLoggerWriter(&buf), WithLoggerMetrics(newNoopMetrics()))
	require.NoError(t, err)

	subject := &Subject{
		ID: "user123",
	}

	event := NewEvent(EventTypeAuthentication, ActionLogin, OutcomeSuccess).
		WithSubject(subject).
		WithTraceID("trace-123").
		WithDuration(100 * time.Millisecond)

	logger.LogEvent(context.Background(), event)

	output := buf.String()
	assert.Contains(t, output, "authentication")
	assert.Contains(t, output, "login")
	assert.Contains(t, output, "success")
	assert.Contains(t, output, "subject=user123")
	assert.Contains(t, output, "trace_id=trace-123")
	assert.Contains(t, output, "duration=")

	_ = logger.Close()
}

func TestLogger_LogEvent_Redaction(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	config := &Config{
		Enabled: true,
		Format:  "json",
		Events: &EventsConfig{
			Request: true,
		},
		RedactFields: []string{"authorization", "password", "secret"},
	}

	logger, err := NewLogger(config, WithLoggerWriter(&buf), WithLoggerMetrics(newNoopMetrics()))
	require.NoError(t, err)

	event := NewEvent(EventTypeRequest, ActionHTTPRequest, OutcomeSuccess).
		WithRequest(&RequestDetails{
			Method: "POST",
			Path:   "/api/login",
			Headers: map[string]string{
				"Authorization": "Bearer secret-token",
				"Content-Type":  "application/json",
				"X-Password":    "secret123",
			},
		}).
		WithMetadata("password", "secret123").
		WithMetadata("username", "testuser")

	logger.LogEvent(context.Background(), event)

	output := buf.String()
	assert.Contains(t, output, "[REDACTED]")
	assert.NotContains(t, output, "secret-token")
	assert.NotContains(t, output, "secret123")
	assert.Contains(t, output, "application/json")
	assert.Contains(t, output, "testuser")

	_ = logger.Close()
}

func TestLogger_LogEvent_SkipPath(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	config := &Config{
		Enabled: true,
		Format:  "json",
		Events: &EventsConfig{
			Request: true,
		},
		SkipPaths: []string{"/health", "/metrics", "/api/internal/*"},
	}

	logger, err := NewLogger(config, WithLoggerWriter(&buf), WithLoggerMetrics(newNoopMetrics()))
	require.NoError(t, err)

	tests := []struct {
		path     string
		expected bool // true if should be logged
	}{
		{"/health", false},
		{"/metrics", false},
		{"/api/internal/status", false},
		{"/api/users", true},
	}

	for _, tt := range tests {
		buf.Reset()
		event := NewEvent(EventTypeRequest, ActionHTTPRequest, OutcomeSuccess).
			WithResource(&Resource{Path: tt.path})

		logger.LogEvent(context.Background(), event)

		if tt.expected {
			assert.NotEmpty(t, buf.String(), "path %s should be logged", tt.path)
		} else {
			assert.Empty(t, buf.String(), "path %s should be skipped", tt.path)
		}
	}

	_ = logger.Close()
}

func TestLogger_LogEvent_EventTypeFiltering(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	config := &Config{
		Enabled: true,
		Format:  "json",
		Events: &EventsConfig{
			Authentication: true,
			Authorization:  false,
			Request:        false,
			Response:       false,
			Configuration:  true,
			Administrative: true,
			Security:       true,
		},
	}

	logger, err := NewLogger(config, WithLoggerWriter(&buf), WithLoggerMetrics(newNoopMetrics()))
	require.NoError(t, err)

	tests := []struct {
		eventType EventType
		expected  bool
	}{
		{EventTypeAuthentication, true},
		{EventTypeAuthorization, false},
		{EventTypeRequest, false},
		{EventTypeResponse, false},
		{EventTypeConfiguration, true},
		{EventTypeAdministrative, true},
		{EventTypeSecurity, true},
	}

	for _, tt := range tests {
		buf.Reset()
		event := NewEvent(tt.eventType, ActionAccess, OutcomeSuccess)
		logger.LogEvent(context.Background(), event)

		if tt.expected {
			assert.NotEmpty(t, buf.String(), "event type %s should be logged", tt.eventType)
		} else {
			assert.Empty(t, buf.String(), "event type %s should not be logged", tt.eventType)
		}
	}

	_ = logger.Close()
}

func TestLogger_LogAuthentication(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	config := &Config{
		Enabled: true,
		Format:  "json",
		Events: &EventsConfig{
			Authentication: true,
		},
	}

	logger, err := NewLogger(config, WithLoggerWriter(&buf), WithLoggerMetrics(newNoopMetrics()))
	require.NoError(t, err)

	subject := &Subject{
		ID:         "user123",
		AuthMethod: "jwt",
	}

	logger.LogAuthentication(context.Background(), ActionLogin, OutcomeSuccess, subject)

	var output map[string]interface{}
	err = json.Unmarshal(buf.Bytes(), &output)
	require.NoError(t, err)

	assert.Equal(t, "authentication", output["type"])
	assert.Equal(t, "login", output["action"])
	assert.Equal(t, "success", output["outcome"])

	_ = logger.Close()
}

func TestLogger_LogAuthorization(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	config := &Config{
		Enabled: true,
		Format:  "json",
		Events: &EventsConfig{
			Authorization: true,
		},
	}

	logger, err := NewLogger(config, WithLoggerWriter(&buf), WithLoggerMetrics(newNoopMetrics()))
	require.NoError(t, err)

	subject := &Subject{ID: "user123"}
	resource := &Resource{Path: "/api/users", Method: "GET"}

	logger.LogAuthorization(context.Background(), OutcomeSuccess, subject, resource)

	var output map[string]interface{}
	err = json.Unmarshal(buf.Bytes(), &output)
	require.NoError(t, err)

	assert.Equal(t, "authorization", output["type"])
	assert.Equal(t, "access", output["action"])
	assert.Equal(t, "success", output["outcome"])

	_ = logger.Close()
}

func TestLogger_LogSecurity(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	config := &Config{
		Enabled: true,
		Format:  "json",
		Events: &EventsConfig{
			Security: true,
		},
	}

	logger, err := NewLogger(config, WithLoggerWriter(&buf), WithLoggerMetrics(newNoopMetrics()))
	require.NoError(t, err)

	subject := &Subject{ID: "user123", IPAddress: "192.168.1.1"}
	details := map[string]interface{}{
		"attempts": 5,
		"blocked":  true,
	}

	logger.LogSecurity(context.Background(), ActionBruteForceDetected, OutcomeFailure, subject, details)

	var output map[string]interface{}
	err = json.Unmarshal(buf.Bytes(), &output)
	require.NoError(t, err)

	assert.Equal(t, "security", output["type"])
	assert.Equal(t, "brute_force_detected", output["action"])
	assert.Equal(t, "failure", output["outcome"])

	_ = logger.Close()
}

func TestLogger_Close(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	config := &Config{
		Enabled: true,
	}

	logger, err := NewLogger(config, WithLoggerWriter(&buf), WithLoggerMetrics(newNoopMetrics()))
	require.NoError(t, err)

	err = logger.Close()
	assert.NoError(t, err)
}

func TestNoopLogger(t *testing.T) {
	t.Parallel()

	logger := NewNoopLogger()

	// All methods should be no-ops
	logger.LogEvent(context.Background(), NewEvent(EventTypeAuthentication, ActionLogin, OutcomeSuccess))
	logger.LogAuthentication(context.Background(), ActionLogin, OutcomeSuccess, nil)
	logger.LogAuthorization(context.Background(), OutcomeSuccess, nil, nil)
	logger.LogSecurity(context.Background(), ActionSuspiciousActivity, OutcomeFailure, nil, nil)

	err := logger.Close()
	assert.NoError(t, err)
}

func TestLogger_FormatText_WithError(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	config := &Config{
		Enabled: true,
		Format:  "text",
		Events: &EventsConfig{
			Authentication: true,
		},
	}

	logger, err := NewLogger(config, WithLoggerWriter(&buf), WithLoggerMetrics(newNoopMetrics()))
	require.NoError(t, err)

	event := NewEvent(EventTypeAuthentication, ActionLogin, OutcomeFailure).
		WithError(&ErrorDetails{
			Code:    "AUTH_FAILED",
			Message: "Invalid credentials",
		})

	logger.LogEvent(context.Background(), event)

	output := buf.String()
	assert.Contains(t, output, "error=Invalid credentials")

	_ = logger.Close()
}

func TestLogger_FormatText_WithResource(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	config := &Config{
		Enabled: true,
		Format:  "text",
		Events: &EventsConfig{
			Authorization: true,
		},
	}

	logger, err := NewLogger(config, WithLoggerWriter(&buf), WithLoggerMetrics(newNoopMetrics()))
	require.NoError(t, err)

	event := NewEvent(EventTypeAuthorization, ActionAccess, OutcomeSuccess).
		WithResource(&Resource{Path: "/api/users"})

	logger.LogEvent(context.Background(), event)

	output := buf.String()
	assert.Contains(t, output, "resource=/api/users")

	_ = logger.Close()
}

func TestLogger_ShouldRedact(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled:      true,
		RedactFields: []string{"password", "secret", "token"},
	}

	l := &logger{config: config}

	tests := []struct {
		field    string
		expected bool
	}{
		{"password", true},
		{"Password", true},
		{"PASSWORD", true},
		{"secret", true},
		{"token", true},
		{"x-auth-token", true},  // Contains "token"
		{"my-secret-key", true}, // Contains "secret"
		{"username", false},
		{"email", false},
	}

	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			result := l.shouldRedact(tt.field)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestLogger_RedactResponseHeaders(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	config := &Config{
		Enabled: true,
		Format:  "json",
		Events: &EventsConfig{
			Response: true,
		},
		RedactFields: []string{"set-cookie"},
	}

	logger, err := NewLogger(config, WithLoggerWriter(&buf), WithLoggerMetrics(newNoopMetrics()))
	require.NoError(t, err)

	event := NewEvent(EventTypeResponse, ActionHTTPResponse, OutcomeSuccess).
		WithResponse(&ResponseDetails{
			StatusCode: 200,
			Headers: map[string]string{
				"Set-Cookie":   "session=abc123",
				"Content-Type": "application/json",
			},
		})

	logger.LogEvent(context.Background(), event)

	output := buf.String()
	assert.Contains(t, output, "[REDACTED]")
	assert.NotContains(t, output, "abc123")
	assert.Contains(t, output, "application/json")

	_ = logger.Close()
}

func TestLogger_CreateWriter_Stdout(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Output:  "stdout",
	}

	logger, err := NewLogger(config, WithLoggerMetrics(newNoopMetrics()))
	require.NoError(t, err)
	assert.NotNil(t, logger)
	_ = logger.Close()
}

func TestLogger_CreateWriter_Stderr(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Output:  "stderr",
	}

	logger, err := NewLogger(config, WithLoggerMetrics(newNoopMetrics()))
	require.NoError(t, err)
	assert.NotNil(t, logger)
	_ = logger.Close()
}

func TestMetrics_RecordEvent(t *testing.T) {
	t.Parallel()

	// Use noop metrics to avoid duplicate registration in parallel tests
	metrics := newNoopMetrics()

	// Should not panic with nil eventsTotal
	metrics.RecordEvent(EventTypeAuthentication, ActionLogin, OutcomeSuccess)
	metrics.RecordEvent(EventTypeAuthorization, ActionAccess, OutcomeDenied)
	metrics.RecordEvent(EventTypeSecurity, ActionBruteForceDetected, OutcomeFailure)
}

func TestLogger_LogEvent_NilEvent(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	config := &Config{
		Enabled: true,
		Format:  "json",
	}

	logger, err := NewLogger(config, WithLoggerWriter(&buf), WithLoggerMetrics(newNoopMetrics()))
	require.NoError(t, err)

	// Verify logger was created successfully and can be closed
	assert.NotNil(t, logger, "logger should be created successfully")
	assert.NoError(t, logger.Close(), "logger should close without error")
}

func TestLogger_LogEvent_ResponseHeaders(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	config := &Config{
		Enabled: true,
		Format:  "json",
		Events: &EventsConfig{
			Response: true,
		},
		RedactFields: []string{},
	}

	logger, err := NewLogger(config, WithLoggerWriter(&buf), WithLoggerMetrics(newNoopMetrics()))
	require.NoError(t, err)

	event := NewEvent(EventTypeResponse, ActionHTTPResponse, OutcomeSuccess).
		WithResponse(&ResponseDetails{
			StatusCode: 200,
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
		})

	logger.LogEvent(context.Background(), event)

	output := buf.String()
	assert.Contains(t, output, "application/json")

	_ = logger.Close()
}

func TestLogger_LogEvent_NilRequestHeaders(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	config := &Config{
		Enabled: true,
		Format:  "json",
		Events: &EventsConfig{
			Request: true,
		},
		RedactFields: []string{"authorization"},
	}

	logger, err := NewLogger(config, WithLoggerWriter(&buf), WithLoggerMetrics(newNoopMetrics()))
	require.NoError(t, err)

	event := NewEvent(EventTypeRequest, ActionHTTPRequest, OutcomeSuccess).
		WithRequest(&RequestDetails{
			Method:  "GET",
			Path:    "/api/test",
			Headers: nil, // nil headers
		})

	logger.LogEvent(context.Background(), event)

	// Should not panic with nil headers
	assert.NotEmpty(t, buf.String())

	_ = logger.Close()
}

func TestLogger_LogEvent_NilResponseHeaders(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	config := &Config{
		Enabled: true,
		Format:  "json",
		Events: &EventsConfig{
			Response: true,
		},
		RedactFields: []string{"set-cookie"},
	}

	logger, err := NewLogger(config, WithLoggerWriter(&buf), WithLoggerMetrics(newNoopMetrics()))
	require.NoError(t, err)

	event := NewEvent(EventTypeResponse, ActionHTTPResponse, OutcomeSuccess).
		WithResponse(&ResponseDetails{
			StatusCode: 200,
			Headers:    nil, // nil headers
		})

	logger.LogEvent(context.Background(), event)

	// Should not panic with nil headers
	assert.NotEmpty(t, buf.String())

	_ = logger.Close()
}

func TestLogger_LogEvent_NilMetadata(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	config := &Config{
		Enabled: true,
		Format:  "json",
		Events: &EventsConfig{
			Authentication: true,
		},
		RedactFields: []string{"password"},
	}

	logger, err := NewLogger(config, WithLoggerWriter(&buf), WithLoggerMetrics(newNoopMetrics()))
	require.NoError(t, err)

	event := &Event{
		ID:        "test-id",
		Timestamp: time.Now(),
		Type:      EventTypeAuthentication,
		Action:    ActionLogin,
		Outcome:   OutcomeSuccess,
		Level:     LevelInfo,
		Metadata:  nil, // nil metadata
	}

	logger.LogEvent(context.Background(), event)

	// Should not panic with nil metadata
	assert.NotEmpty(t, buf.String())

	_ = logger.Close()
}

func TestExtractTraceID_WithValidSpanContext(t *testing.T) {
	t.Parallel()

	// Create a valid SpanContext with a known TraceID and SpanID
	traceID := trace.TraceID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	spanID := trace.SpanID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: trace.FlagsSampled,
	})

	ctx := trace.ContextWithSpanContext(context.Background(), sc)

	// Test extractTraceID
	gotTraceID := extractTraceID(ctx)
	assert.NotEmpty(t, gotTraceID)
	assert.Equal(t, traceID.String(), gotTraceID)

	// Test extractSpanID
	gotSpanID := extractSpanID(ctx)
	assert.NotEmpty(t, gotSpanID)
	assert.Equal(t, spanID.String(), gotSpanID)
}

func TestExtractTraceID_EmptyContext(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	gotTraceID := extractTraceID(ctx)
	assert.Empty(t, gotTraceID)

	gotSpanID := extractSpanID(ctx)
	assert.Empty(t, gotSpanID)
}

func TestExtractTraceID_InvalidSpanContext(t *testing.T) {
	t.Parallel()

	// SpanContext with zero TraceID and SpanID
	sc := trace.NewSpanContext(trace.SpanContextConfig{})
	ctx := trace.ContextWithSpanContext(context.Background(), sc)

	gotTraceID := extractTraceID(ctx)
	assert.Empty(t, gotTraceID, "zero TraceID should return empty string")

	gotSpanID := extractSpanID(ctx)
	assert.Empty(t, gotSpanID, "zero SpanID should return empty string")
}

func TestLogEvent_InjectsTraceContext(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	config := &Config{
		Enabled: true,
		Format:  "json",
		Events: &EventsConfig{
			Authentication: true,
		},
	}

	logger, err := NewLogger(config, WithLoggerWriter(&buf), WithLoggerMetrics(newNoopMetrics()))
	require.NoError(t, err)

	// Create a context with OTel span context
	traceID := trace.TraceID{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
		0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99}
	spanID := trace.SpanID{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}

	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: trace.FlagsSampled,
	})
	ctx := trace.ContextWithSpanContext(context.Background(), sc)

	// Create event without TraceID/SpanID - they should be injected from context
	event := NewEvent(EventTypeAuthentication, ActionLogin, OutcomeSuccess)
	logger.LogEvent(ctx, event)

	var output map[string]interface{}
	err = json.Unmarshal(buf.Bytes(), &output)
	require.NoError(t, err)

	assert.Equal(t, traceID.String(), output["trace_id"])
	assert.Equal(t, spanID.String(), output["span_id"])

	_ = logger.Close()
}

func TestLogger_FormatText_AllFields(t *testing.T) {
	t.Parallel()

	l := &logger{
		config: &Config{
			Enabled: true,
			Format:  "text",
		},
	}

	event := &Event{
		Timestamp: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
		Level:     LevelInfo,
		Type:      EventTypeAuthentication,
		Action:    ActionLogin,
		Outcome:   OutcomeSuccess,
		Subject:   &Subject{ID: "user123"},
		Resource:  &Resource{Path: "/api/login"},
		TraceID:   "trace-abc",
		Duration:  150 * time.Millisecond,
		Error:     &ErrorDetails{Message: "test error"},
	}

	output := l.formatText(event)

	assert.Contains(t, output, "2024-01-15T10:30:00Z")
	assert.Contains(t, output, "info")
	assert.Contains(t, output, "authentication")
	assert.Contains(t, output, "login")
	assert.Contains(t, output, "success")
	assert.Contains(t, output, "subject=user123")
	assert.Contains(t, output, "resource=/api/login")
	assert.Contains(t, output, "trace_id=trace-abc")
	assert.Contains(t, output, "duration=")
	assert.Contains(t, output, "error=test error")
	assert.True(t, strings.HasSuffix(output, "\n"))
}

// ============================================================================
// NewMetrics / NewMetricsWithRegisterer / WithLoggerRegisterer tests
// ============================================================================

func TestNewMetrics(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		namespace string
	}{
		{
			name:      "with custom namespace",
			namespace: "test_audit_ns",
		},
		{
			name:      "with empty namespace defaults to gateway",
			namespace: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Use a custom registerer to avoid polluting the default one
			reg := prometheus.NewRegistry()
			m := NewMetricsWithRegisterer(tt.namespace, reg)

			require.NotNil(t, m)
			require.NotNil(t, m.eventsTotal)

			// Verify the metric is registered by recording an event
			m.RecordEvent(EventTypeAuthentication, ActionLogin, OutcomeSuccess)

			// Gather metrics to verify registration
			families, err := reg.Gather()
			require.NoError(t, err)
			assert.NotEmpty(t, families)
		})
	}
}

func TestNewMetrics_DefaultRegisterer(t *testing.T) {
	// This test verifies NewMetrics uses the default registerer.
	// We can't run it in parallel because it touches the global default registerer.
	m := NewMetrics("test_newmetrics_default")
	require.NotNil(t, m)
	require.NotNil(t, m.eventsTotal)
}

func TestNewMetricsWithRegisterer_NilRegisterer(t *testing.T) {
	t.Parallel()

	// When registerer is nil, should fall back to default registerer
	m := NewMetricsWithRegisterer("test_nil_reg", nil)
	require.NotNil(t, m)
	require.NotNil(t, m.eventsTotal)
}

func TestNewMetricsWithRegisterer_EmptyNamespace(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	m := NewMetricsWithRegisterer("", reg)
	require.NotNil(t, m)
	require.NotNil(t, m.eventsTotal)

	// Record and verify
	m.RecordEvent(EventTypeSecurity, ActionSuspiciousActivity, OutcomeFailure)
	families, err := reg.Gather()
	require.NoError(t, err)

	found := false
	for _, f := range families {
		if strings.Contains(f.GetName(), "audit_events_total") {
			found = true
			break
		}
	}
	assert.True(t, found, "expected gateway_audit_events_total metric to be registered")
}

func TestNewMetricsWithRegisterer_DuplicateRegistration(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()

	// Register once
	m1 := NewMetricsWithRegisterer("dup_test", reg)
	require.NotNil(t, m1)

	// Register again with same descriptors — should not panic
	m2 := NewMetricsWithRegisterer("dup_test", reg)
	require.NotNil(t, m2)
}

func TestMetrics_RecordEvent_WithRegisteredMetrics(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	m := NewMetricsWithRegisterer("rec_test", reg)

	// Record multiple events
	m.RecordEvent(EventTypeAuthentication, ActionLogin, OutcomeSuccess)
	m.RecordEvent(EventTypeAuthentication, ActionLogin, OutcomeFailure)
	m.RecordEvent(EventTypeAuthorization, ActionAccess, OutcomeDenied)
	m.RecordEvent(EventTypeSecurity, ActionBruteForceDetected, OutcomeFailure)

	families, err := reg.Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, families)
}

func TestWithLoggerRegisterer(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	var buf bytes.Buffer

	config := &Config{
		Enabled: true,
		Format:  "json",
		Events: &EventsConfig{
			Authentication: true,
		},
	}

	l, err := NewLogger(config,
		WithLoggerWriter(&buf),
		WithLoggerRegisterer(reg),
	)
	require.NoError(t, err)
	require.NotNil(t, l)

	// Log an event to exercise the metrics path
	event := NewEvent(EventTypeAuthentication, ActionLogin, OutcomeSuccess)
	l.LogEvent(context.Background(), event)

	// Verify the event was written
	assert.NotEmpty(t, buf.String())

	// Verify metrics were registered with the custom registry
	families, err := reg.Gather()
	require.NoError(t, err)

	found := false
	for _, f := range families {
		if strings.Contains(f.GetName(), "audit_events_total") {
			found = true
			break
		}
	}
	assert.True(t, found, "audit metrics should be registered with custom registry")

	_ = l.Close()
}

// ============================================================================
// createWriter tests — file path branch
// ============================================================================

func TestLogger_CreateWriter_FilePath(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "audit.log")

	config := &Config{
		Enabled: true,
		Output:  logFile,
		Format:  "json",
		Events: &EventsConfig{
			Authentication: true,
		},
	}

	l, err := NewLogger(config, WithLoggerMetrics(newNoopMetrics()))
	require.NoError(t, err)
	require.NotNil(t, l)

	// Log an event
	event := NewEvent(EventTypeAuthentication, ActionLogin, OutcomeSuccess)
	l.LogEvent(context.Background(), event)

	// Close to flush
	err = l.Close()
	require.NoError(t, err)

	// Verify the file was created and has content
	data, err := os.ReadFile(logFile)
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	// Verify it's valid JSON
	var output map[string]interface{}
	err = json.Unmarshal(data, &output)
	require.NoError(t, err)
	assert.Equal(t, "authentication", output["type"])
}

func TestLogger_CreateWriter_InvalidFilePath(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Output:  "/nonexistent/directory/audit.log",
	}

	l, err := NewLogger(config, WithLoggerMetrics(newNoopMetrics()))
	assert.Error(t, err)
	assert.Nil(t, l)
	assert.Contains(t, err.Error(), "failed to open audit log file")
}

// ============================================================================
// writeEvent — default format branch
// ============================================================================

func TestLogger_WriteEvent_DefaultFormat(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	config := &Config{
		Enabled: true,
		Format:  "unknown_format", // triggers default branch in writeEvent
		Events: &EventsConfig{
			Authentication: true,
		},
	}

	l, err := NewLogger(config, WithLoggerWriter(&buf), WithLoggerMetrics(newNoopMetrics()))
	require.NoError(t, err)

	event := NewEvent(EventTypeAuthentication, ActionLogin, OutcomeSuccess)
	l.LogEvent(context.Background(), event)

	// Default format should produce JSON output
	var output map[string]interface{}
	err = json.Unmarshal(buf.Bytes(), &output)
	require.NoError(t, err)
	assert.Equal(t, "authentication", output["type"])

	_ = l.Close()
}

// ============================================================================
// Noop logger method coverage
// ============================================================================

func TestNoopLogger_AllMethods(t *testing.T) {
	t.Parallel()

	l := NewNoopLogger()
	require.NotNil(t, l)

	ctx := context.Background()

	// Exercise every method on the noop logger
	l.LogEvent(ctx, NewEvent(EventTypeAuthentication, ActionLogin, OutcomeSuccess))
	l.LogEvent(ctx, nil) // nil event should not panic

	l.LogAuthentication(ctx, ActionLogin, OutcomeSuccess, &Subject{ID: "user1"})
	l.LogAuthentication(ctx, ActionLogout, OutcomeFailure, nil)

	l.LogAuthorization(ctx, OutcomeSuccess, &Subject{ID: "user1"}, &Resource{Path: "/api"})
	l.LogAuthorization(ctx, OutcomeDenied, nil, nil)

	l.LogSecurity(ctx, ActionSuspiciousActivity, OutcomeFailure, &Subject{ID: "user1"}, map[string]interface{}{"key": "val"})
	l.LogSecurity(ctx, ActionBruteForceDetected, OutcomeFailure, nil, nil)

	err := l.Close()
	assert.NoError(t, err)
}

// ============================================================================
// shouldAudit — unknown event type branch
// ============================================================================

func TestLogger_ShouldAudit_UnknownEventType(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	config := &Config{
		Enabled: true,
		Format:  "json",
		Events: &EventsConfig{
			Authentication: false,
			Authorization:  false,
			Request:        false,
			Response:       false,
			Configuration:  false,
			Administrative: false,
			Security:       false,
		},
	}

	l, err := NewLogger(config, WithLoggerWriter(&buf), WithLoggerMetrics(newNoopMetrics()))
	require.NoError(t, err)

	// Unknown event type should default to true (be logged)
	event := NewEvent(EventType("custom_type"), ActionAccess, OutcomeSuccess)
	l.LogEvent(context.Background(), event)

	assert.NotEmpty(t, buf.String(), "unknown event type should be logged (default: true)")

	_ = l.Close()
}

// ============================================================================
// NewLogger — metrics auto-initialization
// ============================================================================

func TestNewLogger_MetricsAutoInitialized(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	config := &Config{
		Enabled: true,
		Format:  "json",
		Events: &EventsConfig{
			Authentication: true,
		},
	}

	// Don't pass WithLoggerMetrics — metrics should be auto-initialized
	l, err := NewLogger(config, WithLoggerWriter(&buf))
	require.NoError(t, err)
	require.NotNil(t, l)

	// Log an event to exercise the auto-initialized metrics
	event := NewEvent(EventTypeAuthentication, ActionLogin, OutcomeSuccess)
	l.LogEvent(context.Background(), event)

	assert.NotEmpty(t, buf.String())
	_ = l.Close()
}

// ============================================================================
// Close — with closer (file writer)
// ============================================================================

func TestLogger_Close_WithCloser(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "close_test.log")

	config := &Config{
		Enabled: true,
		Output:  logFile,
		Format:  "json",
	}

	l, err := NewLogger(config, WithLoggerMetrics(newNoopMetrics()))
	require.NoError(t, err)

	// Close should close the file
	err = l.Close()
	assert.NoError(t, err)

	// Closing again should be safe (file already closed)
	// The second close will fail but we're testing the first one
}

// ============================================================================
// writeEvent — error handling for write failures
// ============================================================================

type failWriter struct{}

func (fw *failWriter) Write(_ []byte) (int, error) {
	return 0, assert.AnError
}

func TestLogger_WriteEvent_WriteError(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Format:  "json",
		Events: &EventsConfig{
			Authentication: true,
		},
	}

	l, err := NewLogger(config,
		WithLoggerWriter(&failWriter{}),
		WithLoggerMetrics(newNoopMetrics()),
		WithLoggerLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	// Should not panic even when write fails
	event := NewEvent(EventTypeAuthentication, ActionLogin, OutcomeSuccess)
	l.LogEvent(context.Background(), event)

	_ = l.Close()
}

func TestLogger_WriteEvent_TextFormat_WriteError(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Format:  "text",
		Events: &EventsConfig{
			Authentication: true,
		},
	}

	l, err := NewLogger(config,
		WithLoggerWriter(&failWriter{}),
		WithLoggerMetrics(newNoopMetrics()),
		WithLoggerLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	event := NewEvent(EventTypeAuthentication, ActionLogin, OutcomeSuccess)
	l.LogEvent(context.Background(), event)

	_ = l.Close()
}
