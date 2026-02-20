package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel/trace"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// Constants for audit logging.
const (
	redactedValue = "[REDACTED]"
	formatJSON    = "json"
	formatText    = "text"
)

// Logger is the audit logger interface.
type Logger interface {
	// LogEvent logs an audit event.
	LogEvent(ctx context.Context, event *Event)

	// LogAuthentication logs an authentication event.
	LogAuthentication(ctx context.Context, action Action, outcome Outcome, subject *Subject)

	// LogAuthorization logs an authorization event.
	LogAuthorization(ctx context.Context, outcome Outcome, subject *Subject, resource *Resource)

	// LogSecurity logs a security event.
	LogSecurity(ctx context.Context, action Action, outcome Outcome, subject *Subject, details map[string]interface{})

	// Close closes the logger.
	Close() error
}

// logger implements the Logger interface.
type logger struct {
	config  *Config
	writer  io.Writer
	mu      sync.Mutex
	logger  observability.Logger
	metrics *Metrics
	closer  io.Closer
}

// Metrics contains audit metrics.
type Metrics struct {
	eventsTotal *prometheus.CounterVec
}

// NewMetrics creates new audit metrics registered with the default
// registerer.
func NewMetrics(namespace string) *Metrics {
	return NewMetricsWithRegisterer(namespace, prometheus.DefaultRegisterer)
}

// NewMetricsWithRegisterer creates new audit metrics registered with
// the provided registerer. This allows the metrics to be registered
// with the gateway's custom registry so they appear on the /metrics
// endpoint.
func NewMetricsWithRegisterer(namespace string, registerer prometheus.Registerer) *Metrics {
	if namespace == "" {
		namespace = "gateway"
	}
	if registerer == nil {
		registerer = prometheus.DefaultRegisterer
	}

	m := &Metrics{
		eventsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: "audit",
				Name:      "events_total",
				Help:      "Total number of audit events",
			},
			[]string{"type", "action", "outcome"},
		),
	}

	// Register with the provided registerer, ignoring duplicate
	// registration errors (safe because descriptors are identical).
	_ = registerer.Register(m.eventsTotal)

	m.Init()

	return m
}

// Init pre-populates common label combinations with zero values so
// that audit Vec metrics appear in /metrics output immediately after
// startup. Prometheus *Vec types only emit metric lines after
// WithLabelValues() is called at least once. This method is
// idempotent and safe to call multiple times.
func (m *Metrics) Init() {
	if m.eventsTotal == nil {
		return
	}

	types := []string{"authentication", "authorization", "request"}
	actions := []string{"access", "modify"}
	outcomes := []string{"success", "failure"}

	for _, t := range types {
		for _, a := range actions {
			for _, o := range outcomes {
				m.eventsTotal.WithLabelValues(t, a, o)
			}
		}
	}
}

// RecordEvent records an audit event metric.
func (m *Metrics) RecordEvent(eventType EventType, action Action, outcome Outcome) {
	if m.eventsTotal == nil {
		return
	}
	m.eventsTotal.WithLabelValues(string(eventType), string(action), string(outcome)).Inc()
}

// LoggerOption is a functional option for the logger.
type LoggerOption func(*logger)

// WithLoggerLogger sets the observability logger.
func WithLoggerLogger(l observability.Logger) LoggerOption {
	return func(lg *logger) {
		lg.logger = l
	}
}

// WithLoggerMetrics sets the metrics.
func WithLoggerMetrics(metrics *Metrics) LoggerOption {
	return func(lg *logger) {
		lg.metrics = metrics
	}
}

// WithLoggerWriter sets the writer.
func WithLoggerWriter(writer io.Writer) LoggerOption {
	return func(lg *logger) {
		lg.writer = writer
	}
}

// WithLoggerRegisterer sets the Prometheus registerer for audit
// metrics. When provided, audit metrics are registered with this
// registerer instead of the global default, ensuring they appear on
// the gateway's custom /metrics endpoint.
func WithLoggerRegisterer(registerer prometheus.Registerer) LoggerOption {
	return func(lg *logger) {
		lg.metrics = NewMetricsWithRegisterer("gateway", registerer)
	}
}

// NewLogger creates a new audit logger.
func NewLogger(config *Config, opts ...LoggerOption) (Logger, error) {
	if config == nil {
		config = DefaultConfig()
	}

	l := &logger{
		config: config,
		logger: observability.NopLogger(),
	}

	for _, opt := range opts {
		opt(l)
	}

	// Initialize metrics if not provided
	if l.metrics == nil {
		l.metrics = NewMetrics("gateway")
	}

	// Initialize writer if not provided
	if l.writer == nil {
		writer, closer, err := l.createWriter()
		if err != nil {
			return nil, err
		}
		l.writer = writer
		l.closer = closer
	}

	return l, nil
}

// createWriter creates the output writer based on configuration.
func (l *logger) createWriter() (io.Writer, io.Closer, error) {
	output := l.config.GetEffectiveOutput()

	switch output {
	case "stdout":
		return os.Stdout, nil, nil
	case "stderr":
		return os.Stderr, nil, nil
	default:
		// Assume it's a file path - path comes from trusted configuration
		//nolint:gosec // G304: path from config is trusted
		file, err := os.OpenFile(output, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to open audit log file: %w", err)
		}
		return file, file, nil
	}
}

// LogEvent logs an audit event.
func (l *logger) LogEvent(ctx context.Context, event *Event) {
	if !l.config.Enabled {
		return
	}

	// Check if this event type should be audited
	if !l.shouldAudit(event) {
		return
	}

	// Check if path should be skipped
	if event.Resource != nil && l.config.ShouldSkipPath(event.Resource.Path) {
		return
	}

	// Extract trace context
	if event.TraceID == "" {
		event.TraceID = extractTraceID(ctx)
	}
	if event.SpanID == "" {
		event.SpanID = extractSpanID(ctx)
	}

	// Redact sensitive fields
	l.redactEvent(event)

	// Record metrics
	l.metrics.RecordEvent(event.Type, event.Action, event.Outcome)

	// Write the event
	l.writeEvent(event)
}

// shouldAudit checks if an event should be audited based on configuration.
func (l *logger) shouldAudit(event *Event) bool {
	switch event.Type {
	case EventTypeAuthentication:
		return l.config.ShouldAuditAuthentication()
	case EventTypeAuthorization:
		return l.config.ShouldAuditAuthorization()
	case EventTypeRequest:
		return l.config.ShouldAuditRequest()
	case EventTypeResponse:
		return l.config.ShouldAuditResponse()
	case EventTypeConfiguration:
		return l.config.ShouldAuditConfiguration()
	case EventTypeAdministrative:
		return l.config.ShouldAuditAdministrative()
	case EventTypeSecurity:
		return l.config.ShouldAuditSecurity()
	default:
		return true
	}
}

// redactEvent redacts sensitive fields from the event.
func (l *logger) redactEvent(event *Event) {
	if len(l.config.RedactFields) == 0 {
		return
	}

	l.redactRequestHeaders(event)
	l.redactResponseHeaders(event)
	l.redactMetadata(event)
}

// redactRequestHeaders redacts sensitive request headers.
func (l *logger) redactRequestHeaders(event *Event) {
	if event.Request == nil || event.Request.Headers == nil {
		return
	}
	for key := range event.Request.Headers {
		if l.shouldRedact(key) {
			event.Request.Headers[key] = redactedValue
		}
	}
}

// redactResponseHeaders redacts sensitive response headers.
func (l *logger) redactResponseHeaders(event *Event) {
	if event.Response == nil || event.Response.Headers == nil {
		return
	}
	for key := range event.Response.Headers {
		if l.shouldRedact(key) {
			event.Response.Headers[key] = redactedValue
		}
	}
}

// redactMetadata redacts sensitive metadata.
func (l *logger) redactMetadata(event *Event) {
	if event.Metadata == nil {
		return
	}
	for key := range event.Metadata {
		if l.shouldRedact(key) {
			event.Metadata[key] = redactedValue
		}
	}
}

// shouldRedact checks if a field should be redacted.
func (l *logger) shouldRedact(field string) bool {
	lowerField := strings.ToLower(field)
	for _, redactField := range l.config.RedactFields {
		if strings.EqualFold(redactField, lowerField) {
			return true
		}
		// Check for partial match
		if strings.Contains(lowerField, strings.ToLower(redactField)) {
			return true
		}
	}
	return false
}

// writeEvent writes the event to the output.
func (l *logger) writeEvent(event *Event) {
	l.mu.Lock()
	defer l.mu.Unlock()

	var output []byte
	var err error

	switch l.config.GetEffectiveFormat() {
	case formatJSON:
		output, err = json.Marshal(event)
		if err != nil {
			l.logger.Error("failed to marshal audit event", observability.Error(err))
			return
		}
		output = append(output, '\n')
	case formatText:
		output = []byte(l.formatText(event))
	default:
		output, err = json.Marshal(event)
		if err != nil {
			l.logger.Error("failed to marshal audit event", observability.Error(err))
			return
		}
		output = append(output, '\n')
	}

	if _, err := l.writer.Write(output); err != nil {
		l.logger.Error("failed to write audit event", observability.Error(err))
	}
}

// formatText formats an event as text.
func (l *logger) formatText(event *Event) string {
	var sb strings.Builder

	sb.WriteString(event.Timestamp.Format(time.RFC3339))
	sb.WriteString(" ")
	sb.WriteString(string(event.Level))
	sb.WriteString(" ")
	sb.WriteString(string(event.Type))
	sb.WriteString(" ")
	sb.WriteString(string(event.Action))
	sb.WriteString(" ")
	sb.WriteString(string(event.Outcome))

	if event.Subject != nil {
		sb.WriteString(" subject=")
		sb.WriteString(event.Subject.ID)
	}

	if event.Resource != nil {
		sb.WriteString(" resource=")
		sb.WriteString(event.Resource.Path)
	}

	if event.TraceID != "" {
		sb.WriteString(" trace_id=")
		sb.WriteString(event.TraceID)
	}

	if event.Duration > 0 {
		sb.WriteString(" duration=")
		sb.WriteString(event.Duration.String())
	}

	if event.Error != nil {
		sb.WriteString(" error=")
		sb.WriteString(event.Error.Message)
	}

	sb.WriteString("\n")
	return sb.String()
}

// LogAuthentication logs an authentication event.
func (l *logger) LogAuthentication(
	ctx context.Context,
	action Action,
	outcome Outcome,
	subject *Subject,
) {
	event := AuthenticationEvent(action, outcome, subject)
	l.LogEvent(ctx, event)
}

// LogAuthorization logs an authorization event.
func (l *logger) LogAuthorization(
	ctx context.Context,
	outcome Outcome,
	subject *Subject,
	resource *Resource,
) {
	event := AuthorizationEvent(outcome, subject, resource)
	l.LogEvent(ctx, event)
}

// LogSecurity logs a security event.
func (l *logger) LogSecurity(
	ctx context.Context,
	action Action,
	outcome Outcome,
	subject *Subject,
	details map[string]interface{},
) {
	event := SecurityEvent(action, outcome, subject, details)
	l.LogEvent(ctx, event)
}

// Close closes the logger.
func (l *logger) Close() error {
	if l.closer != nil {
		return l.closer.Close()
	}
	return nil
}

// extractTraceID extracts the trace ID from the OpenTelemetry span context.
// Returns an empty string when no valid trace context is present.
func extractTraceID(ctx context.Context) string {
	sc := trace.SpanContextFromContext(ctx)
	if sc.HasTraceID() {
		return sc.TraceID().String()
	}
	return ""
}

// extractSpanID extracts the span ID from the OpenTelemetry span context.
// Returns an empty string when no valid span context is present.
func extractSpanID(ctx context.Context) string {
	sc := trace.SpanContextFromContext(ctx)
	if sc.HasSpanID() {
		return sc.SpanID().String()
	}
	return ""
}

// noopLogger is a no-op audit logger.
type noopLogger struct{}

// NewNoopLogger creates a new no-op audit logger.
func NewNoopLogger() Logger {
	return &noopLogger{}
}

func (l *noopLogger) LogEvent(_ context.Context, _ *Event) {}

func (l *noopLogger) LogAuthentication(
	_ context.Context,
	_ Action,
	_ Outcome,
	_ *Subject,
) {
}

func (l *noopLogger) LogAuthorization(
	_ context.Context,
	_ Outcome,
	_ *Subject,
	_ *Resource,
) {
}

func (l *noopLogger) LogSecurity(
	_ context.Context,
	_ Action,
	_ Outcome,
	_ *Subject,
	_ map[string]interface{},
) {
}

func (l *noopLogger) Close() error { return nil }

// Ensure implementations satisfy the interface.
var (
	_ Logger = (*logger)(nil)
	_ Logger = (*noopLogger)(nil)
)
