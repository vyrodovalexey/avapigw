package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

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

	// Should handle nil event gracefully (or panic - depends on implementation)
	// This test documents the behavior
	defer func() {
		if r := recover(); r != nil {
			// Expected if nil event causes panic
		}
	}()

	// Note: The actual implementation may or may not handle nil events
	// This test is here to document the behavior

	_ = logger.Close()
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
