package audit

import (
	"time"

	"github.com/google/uuid"
)

// EventType represents the type of audit event.
type EventType string

// Event types.
const (
	EventTypeAuthentication EventType = "authentication"
	EventTypeAuthorization  EventType = "authorization"
	EventTypeRequest        EventType = "request"
	EventTypeResponse       EventType = "response"
	EventTypeConfiguration  EventType = "configuration"
	EventTypeAdministrative EventType = "administrative"
	EventTypeSecurity       EventType = "security"
)

// Action represents the action being audited.
type Action string

// Common actions.
const (
	// Authentication actions
	ActionLogin          Action = "login"
	ActionLogout         Action = "logout"
	ActionTokenRefresh   Action = "token_refresh"
	ActionTokenRevoke    Action = "token_revoke"
	ActionPasswordChange Action = "password_change"
	ActionMFAChallenge   Action = "mfa_challenge"

	// Authorization actions
	ActionAccess Action = "access"
	ActionDeny   Action = "deny"

	// Request/Response actions
	ActionHTTPRequest  Action = "http_request"
	ActionHTTPResponse Action = "http_response"
	ActionGRPCRequest  Action = "grpc_request"
	ActionGRPCResponse Action = "grpc_response"

	// Configuration actions
	ActionConfigCreate Action = "config_create"
	ActionConfigUpdate Action = "config_update"
	ActionConfigDelete Action = "config_delete"
	ActionConfigReload Action = "config_reload"

	// Administrative actions
	ActionUserCreate   Action = "user_create"
	ActionUserUpdate   Action = "user_update"
	ActionUserDelete   Action = "user_delete"
	ActionRoleAssign   Action = "role_assign"
	ActionRoleRevoke   Action = "role_revoke"
	ActionPolicyCreate Action = "policy_create"
	ActionPolicyUpdate Action = "policy_update"
	ActionPolicyDelete Action = "policy_delete"

	// Security actions
	ActionRateLimitExceeded   Action = "rate_limit_exceeded"
	ActionSuspiciousActivity  Action = "suspicious_activity"
	ActionBruteForceDetected  Action = "brute_force_detected"
	ActionCertificateExpiring Action = "certificate_expiring"
	ActionCertificateExpired  Action = "certificate_expired"
)

// Outcome represents the outcome of an audited action.
type Outcome string

// Outcomes.
const (
	OutcomeSuccess Outcome = "success"
	OutcomeFailure Outcome = "failure"
	OutcomeError   Outcome = "error"
	OutcomeDenied  Outcome = "denied"
)

// Event represents an audit event.
type Event struct {
	// ID is a unique identifier for the event.
	ID string `json:"id"`

	// Timestamp is when the event occurred.
	Timestamp time.Time `json:"timestamp"`

	// Type is the type of event.
	Type EventType `json:"type"`

	// Action is the action being audited.
	Action Action `json:"action"`

	// Outcome is the outcome of the action.
	Outcome Outcome `json:"outcome"`

	// Level is the audit level.
	Level Level `json:"level"`

	// Subject is the entity performing the action.
	Subject *Subject `json:"subject,omitempty"`

	// Resource is the resource being accessed.
	Resource *Resource `json:"resource,omitempty"`

	// Request contains request details.
	Request *RequestDetails `json:"request,omitempty"`

	// Response contains response details.
	Response *ResponseDetails `json:"response,omitempty"`

	// Error contains error details if the action failed.
	Error *ErrorDetails `json:"error,omitempty"`

	// Metadata contains additional metadata.
	Metadata map[string]interface{} `json:"metadata,omitempty"`

	// TraceID is the trace ID for distributed tracing.
	TraceID string `json:"trace_id,omitempty"`

	// SpanID is the span ID for distributed tracing.
	SpanID string `json:"span_id,omitempty"`

	// Duration is how long the action took.
	Duration time.Duration `json:"duration,omitempty"`
}

// Subject represents the entity performing an action.
type Subject struct {
	// ID is the subject identifier.
	ID string `json:"id"`

	// Type is the type of subject (user, service, system).
	Type string `json:"type,omitempty"`

	// Name is the display name.
	Name string `json:"name,omitempty"`

	// Email is the email address.
	Email string `json:"email,omitempty"`

	// Roles are the subject's roles.
	Roles []string `json:"roles,omitempty"`

	// Groups are the subject's groups.
	Groups []string `json:"groups,omitempty"`

	// TenantID is the tenant identifier.
	TenantID string `json:"tenant_id,omitempty"`

	// ClientID is the client identifier for service accounts.
	ClientID string `json:"client_id,omitempty"`

	// IPAddress is the client IP address.
	IPAddress string `json:"ip_address,omitempty"`

	// UserAgent is the client user agent.
	UserAgent string `json:"user_agent,omitempty"`

	// AuthMethod is the authentication method used.
	AuthMethod string `json:"auth_method,omitempty"`
}

// Resource represents the resource being accessed.
type Resource struct {
	// Type is the type of resource.
	Type string `json:"type,omitempty"`

	// ID is the resource identifier.
	ID string `json:"id,omitempty"`

	// Name is the resource name.
	Name string `json:"name,omitempty"`

	// Path is the resource path.
	Path string `json:"path,omitempty"`

	// Service is the service name.
	Service string `json:"service,omitempty"`

	// Method is the HTTP method or gRPC method.
	Method string `json:"method,omitempty"`
}

// RequestDetails contains details about the request.
type RequestDetails struct {
	// Method is the HTTP method.
	Method string `json:"method,omitempty"`

	// Path is the request path.
	Path string `json:"path,omitempty"`

	// Query is the query string.
	Query string `json:"query,omitempty"`

	// Headers are the request headers (sensitive headers redacted).
	Headers map[string]string `json:"headers,omitempty"`

	// Body is the request body (if configured to include).
	Body string `json:"body,omitempty"`

	// ContentType is the content type.
	ContentType string `json:"content_type,omitempty"`

	// ContentLength is the content length.
	ContentLength int64 `json:"content_length,omitempty"`

	// RemoteAddr is the remote address.
	RemoteAddr string `json:"remote_addr,omitempty"`

	// Protocol is the protocol (HTTP/1.1, HTTP/2, gRPC).
	Protocol string `json:"protocol,omitempty"`
}

// ResponseDetails contains details about the response.
type ResponseDetails struct {
	// StatusCode is the HTTP status code.
	StatusCode int `json:"status_code,omitempty"`

	// Headers are the response headers.
	Headers map[string]string `json:"headers,omitempty"`

	// Body is the response body (if configured to include).
	Body string `json:"body,omitempty"`

	// ContentType is the content type.
	ContentType string `json:"content_type,omitempty"`

	// ContentLength is the content length.
	ContentLength int64 `json:"content_length,omitempty"`
}

// ErrorDetails contains details about an error.
type ErrorDetails struct {
	// Code is the error code.
	Code string `json:"code,omitempty"`

	// Message is the error message.
	Message string `json:"message,omitempty"`

	// Details contains additional error details.
	Details map[string]interface{} `json:"details,omitempty"`
}

// NewEvent creates a new audit event with default values.
func NewEvent(eventType EventType, action Action, outcome Outcome) *Event {
	return &Event{
		ID:        generateEventID(),
		Timestamp: time.Now().UTC(),
		Type:      eventType,
		Action:    action,
		Outcome:   outcome,
		Level:     LevelInfo,
		Metadata:  make(map[string]interface{}),
	}
}

// WithSubject sets the subject.
func (e *Event) WithSubject(subject *Subject) *Event {
	e.Subject = subject
	return e
}

// WithResource sets the resource.
func (e *Event) WithResource(resource *Resource) *Event {
	e.Resource = resource
	return e
}

// WithRequest sets the request details.
func (e *Event) WithRequest(request *RequestDetails) *Event {
	e.Request = request
	return e
}

// WithResponse sets the response details.
func (e *Event) WithResponse(response *ResponseDetails) *Event {
	e.Response = response
	return e
}

// WithError sets the error details.
func (e *Event) WithError(err *ErrorDetails) *Event {
	e.Error = err
	return e
}

// WithMetadata adds metadata to the event.
func (e *Event) WithMetadata(key string, value interface{}) *Event {
	if e.Metadata == nil {
		e.Metadata = make(map[string]interface{})
	}
	e.Metadata[key] = value
	return e
}

// WithTraceID sets the trace ID.
func (e *Event) WithTraceID(traceID string) *Event {
	e.TraceID = traceID
	return e
}

// WithSpanID sets the span ID.
func (e *Event) WithSpanID(spanID string) *Event {
	e.SpanID = spanID
	return e
}

// WithDuration sets the duration.
func (e *Event) WithDuration(duration time.Duration) *Event {
	e.Duration = duration
	return e
}

// WithLevel sets the audit level.
func (e *Event) WithLevel(level Level) *Event {
	e.Level = level
	return e
}

// generateEventID generates a unique event ID using UUID v4.
func generateEventID() string {
	return uuid.New().String()
}

// AuthenticationEvent creates an authentication audit event.
func AuthenticationEvent(action Action, outcome Outcome, subject *Subject) *Event {
	return NewEvent(EventTypeAuthentication, action, outcome).
		WithSubject(subject)
}

// AuthorizationEvent creates an authorization audit event.
func AuthorizationEvent(outcome Outcome, subject *Subject, resource *Resource) *Event {
	action := ActionAccess
	if outcome == OutcomeDenied {
		action = ActionDeny
	}
	return NewEvent(EventTypeAuthorization, action, outcome).
		WithSubject(subject).
		WithResource(resource)
}

// RequestEvent creates a request audit event.
func RequestEvent(request *RequestDetails, subject *Subject) *Event {
	action := ActionHTTPRequest
	if request.Protocol == "gRPC" {
		action = ActionGRPCRequest
	}
	return NewEvent(EventTypeRequest, action, OutcomeSuccess).
		WithSubject(subject).
		WithRequest(request)
}

// ResponseEvent creates a response audit event.
func ResponseEvent(response *ResponseDetails, duration time.Duration) *Event {
	action := ActionHTTPResponse
	outcome := OutcomeSuccess
	if response.StatusCode >= 400 {
		outcome = OutcomeFailure
	}
	return NewEvent(EventTypeResponse, action, outcome).
		WithResponse(response).
		WithDuration(duration)
}

// SecurityEvent creates a security audit event.
func SecurityEvent(action Action, outcome Outcome, subject *Subject, details map[string]interface{}) *Event {
	event := NewEvent(EventTypeSecurity, action, outcome).
		WithSubject(subject).
		WithLevel(LevelWarn)
	for k, v := range details {
		event.WithMetadata(k, v)
	}
	return event
}
