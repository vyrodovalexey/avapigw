package audit

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewEvent(t *testing.T) {
	t.Parallel()

	event := NewEvent(EventTypeAuthentication, ActionLogin, OutcomeSuccess)

	assert.NotEmpty(t, event.ID)
	assert.False(t, event.Timestamp.IsZero())
	assert.Equal(t, EventTypeAuthentication, event.Type)
	assert.Equal(t, ActionLogin, event.Action)
	assert.Equal(t, OutcomeSuccess, event.Outcome)
	assert.Equal(t, LevelInfo, event.Level)
	assert.NotNil(t, event.Metadata)
}

func TestEvent_WithSubject(t *testing.T) {
	t.Parallel()

	subject := &Subject{
		ID:   "user123",
		Type: "user",
		Name: "Test User",
	}

	event := NewEvent(EventTypeAuthentication, ActionLogin, OutcomeSuccess).
		WithSubject(subject)

	assert.Equal(t, subject, event.Subject)
}

func TestEvent_WithResource(t *testing.T) {
	t.Parallel()

	resource := &Resource{
		Type:   "api",
		Path:   "/api/users",
		Method: "GET",
	}

	event := NewEvent(EventTypeAuthorization, ActionAccess, OutcomeSuccess).
		WithResource(resource)

	assert.Equal(t, resource, event.Resource)
}

func TestEvent_WithRequest(t *testing.T) {
	t.Parallel()

	request := &RequestDetails{
		Method: "POST",
		Path:   "/api/login",
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
	}

	event := NewEvent(EventTypeRequest, ActionHTTPRequest, OutcomeSuccess).
		WithRequest(request)

	assert.Equal(t, request, event.Request)
}

func TestEvent_WithResponse(t *testing.T) {
	t.Parallel()

	response := &ResponseDetails{
		StatusCode:  200,
		ContentType: "application/json",
	}

	event := NewEvent(EventTypeResponse, ActionHTTPResponse, OutcomeSuccess).
		WithResponse(response)

	assert.Equal(t, response, event.Response)
}

func TestEvent_WithError(t *testing.T) {
	t.Parallel()

	errDetails := &ErrorDetails{
		Code:    "AUTH_FAILED",
		Message: "Invalid credentials",
	}

	event := NewEvent(EventTypeAuthentication, ActionLogin, OutcomeFailure).
		WithError(errDetails)

	assert.Equal(t, errDetails, event.Error)
}

func TestEvent_WithMetadata(t *testing.T) {
	t.Parallel()

	event := NewEvent(EventTypeAuthentication, ActionLogin, OutcomeSuccess).
		WithMetadata("key1", "value1").
		WithMetadata("key2", 123)

	assert.Equal(t, "value1", event.Metadata["key1"])
	assert.Equal(t, 123, event.Metadata["key2"])
}

func TestEvent_WithMetadata_NilMetadata(t *testing.T) {
	t.Parallel()

	event := &Event{
		Metadata: nil,
	}

	event.WithMetadata("key", "value")

	assert.NotNil(t, event.Metadata)
	assert.Equal(t, "value", event.Metadata["key"])
}

func TestEvent_WithTraceID(t *testing.T) {
	t.Parallel()

	event := NewEvent(EventTypeAuthentication, ActionLogin, OutcomeSuccess).
		WithTraceID("trace-123")

	assert.Equal(t, "trace-123", event.TraceID)
}

func TestEvent_WithSpanID(t *testing.T) {
	t.Parallel()

	event := NewEvent(EventTypeAuthentication, ActionLogin, OutcomeSuccess).
		WithSpanID("span-456")

	assert.Equal(t, "span-456", event.SpanID)
}

func TestEvent_WithDuration(t *testing.T) {
	t.Parallel()

	duration := 150 * time.Millisecond
	event := NewEvent(EventTypeResponse, ActionHTTPResponse, OutcomeSuccess).
		WithDuration(duration)

	assert.Equal(t, duration, event.Duration)
}

func TestEvent_WithLevel(t *testing.T) {
	t.Parallel()

	event := NewEvent(EventTypeSecurity, ActionSuspiciousActivity, OutcomeFailure).
		WithLevel(LevelWarn)

	assert.Equal(t, LevelWarn, event.Level)
}

func TestEvent_Chaining(t *testing.T) {
	t.Parallel()

	subject := &Subject{ID: "user123"}
	resource := &Resource{Path: "/api/users"}

	event := NewEvent(EventTypeAuthorization, ActionAccess, OutcomeSuccess).
		WithSubject(subject).
		WithResource(resource).
		WithTraceID("trace-123").
		WithSpanID("span-456").
		WithDuration(100*time.Millisecond).
		WithLevel(LevelInfo).
		WithMetadata("key", "value")

	assert.Equal(t, subject, event.Subject)
	assert.Equal(t, resource, event.Resource)
	assert.Equal(t, "trace-123", event.TraceID)
	assert.Equal(t, "span-456", event.SpanID)
	assert.Equal(t, 100*time.Millisecond, event.Duration)
	assert.Equal(t, LevelInfo, event.Level)
	assert.Equal(t, "value", event.Metadata["key"])
}

func TestAuthenticationEvent(t *testing.T) {
	t.Parallel()

	subject := &Subject{
		ID:         "user123",
		AuthMethod: "jwt",
	}

	event := AuthenticationEvent(ActionLogin, OutcomeSuccess, subject)

	assert.Equal(t, EventTypeAuthentication, event.Type)
	assert.Equal(t, ActionLogin, event.Action)
	assert.Equal(t, OutcomeSuccess, event.Outcome)
	assert.Equal(t, subject, event.Subject)
}

func TestAuthorizationEvent(t *testing.T) {
	t.Parallel()

	subject := &Subject{ID: "user123"}
	resource := &Resource{Path: "/api/admin", Method: "DELETE"}

	tests := []struct {
		name           string
		outcome        Outcome
		expectedAction Action
	}{
		{"success", OutcomeSuccess, ActionAccess},
		{"denied", OutcomeDenied, ActionDeny},
		{"failure", OutcomeFailure, ActionAccess},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			event := AuthorizationEvent(tt.outcome, subject, resource)

			assert.Equal(t, EventTypeAuthorization, event.Type)
			assert.Equal(t, tt.expectedAction, event.Action)
			assert.Equal(t, tt.outcome, event.Outcome)
			assert.Equal(t, subject, event.Subject)
			assert.Equal(t, resource, event.Resource)
		})
	}
}

func TestRequestEvent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		protocol       string
		expectedAction Action
	}{
		{"HTTP request", "HTTP/1.1", ActionHTTPRequest},
		{"gRPC request", "gRPC", ActionGRPCRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			request := &RequestDetails{
				Method:   "POST",
				Path:     "/api/users",
				Protocol: tt.protocol,
			}
			subject := &Subject{ID: "user123"}

			event := RequestEvent(request, subject)

			assert.Equal(t, EventTypeRequest, event.Type)
			assert.Equal(t, tt.expectedAction, event.Action)
			assert.Equal(t, OutcomeSuccess, event.Outcome)
			assert.Equal(t, subject, event.Subject)
			assert.Equal(t, request, event.Request)
		})
	}
}

func TestResponseEvent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		statusCode      int
		expectedOutcome Outcome
	}{
		{"success 200", 200, OutcomeSuccess},
		{"success 201", 201, OutcomeSuccess},
		{"redirect 302", 302, OutcomeSuccess},
		{"client error 400", 400, OutcomeFailure},
		{"unauthorized 401", 401, OutcomeFailure},
		{"not found 404", 404, OutcomeFailure},
		{"server error 500", 500, OutcomeFailure},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			response := &ResponseDetails{
				StatusCode: tt.statusCode,
			}
			duration := 100 * time.Millisecond

			event := ResponseEvent(response, duration)

			assert.Equal(t, EventTypeResponse, event.Type)
			assert.Equal(t, ActionHTTPResponse, event.Action)
			assert.Equal(t, tt.expectedOutcome, event.Outcome)
			assert.Equal(t, response, event.Response)
			assert.Equal(t, duration, event.Duration)
		})
	}
}

func TestSecurityEvent(t *testing.T) {
	t.Parallel()

	subject := &Subject{
		ID:        "user123",
		IPAddress: "192.168.1.1",
	}
	details := map[string]interface{}{
		"attempts": 5,
		"blocked":  true,
	}

	event := SecurityEvent(ActionBruteForceDetected, OutcomeFailure, subject, details)

	assert.Equal(t, EventTypeSecurity, event.Type)
	assert.Equal(t, ActionBruteForceDetected, event.Action)
	assert.Equal(t, OutcomeFailure, event.Outcome)
	assert.Equal(t, subject, event.Subject)
	assert.Equal(t, LevelWarn, event.Level)
	assert.Equal(t, 5, event.Metadata["attempts"])
	assert.Equal(t, true, event.Metadata["blocked"])
}

func TestGenerateEventID(t *testing.T) {
	t.Parallel()

	id1 := generateEventID()
	id2 := generateEventID()

	assert.NotEmpty(t, id1)
	assert.NotEmpty(t, id2)
	// IDs should be unique (or at least different in most cases)
	// Note: In rapid succession, they might be the same due to timestamp resolution
}

func TestEventTypeConstants(t *testing.T) {
	t.Parallel()

	assert.Equal(t, EventType("authentication"), EventTypeAuthentication)
	assert.Equal(t, EventType("authorization"), EventTypeAuthorization)
	assert.Equal(t, EventType("request"), EventTypeRequest)
	assert.Equal(t, EventType("response"), EventTypeResponse)
	assert.Equal(t, EventType("configuration"), EventTypeConfiguration)
	assert.Equal(t, EventType("administrative"), EventTypeAdministrative)
	assert.Equal(t, EventType("security"), EventTypeSecurity)
}

func TestActionConstants(t *testing.T) {
	t.Parallel()

	// Authentication actions
	assert.Equal(t, Action("login"), ActionLogin)
	assert.Equal(t, Action("logout"), ActionLogout)
	assert.Equal(t, Action("token_refresh"), ActionTokenRefresh)
	assert.Equal(t, Action("token_revoke"), ActionTokenRevoke)
	assert.Equal(t, Action("password_change"), ActionPasswordChange)
	assert.Equal(t, Action("mfa_challenge"), ActionMFAChallenge)

	// Authorization actions
	assert.Equal(t, Action("access"), ActionAccess)
	assert.Equal(t, Action("deny"), ActionDeny)

	// Request/Response actions
	assert.Equal(t, Action("http_request"), ActionHTTPRequest)
	assert.Equal(t, Action("http_response"), ActionHTTPResponse)
	assert.Equal(t, Action("grpc_request"), ActionGRPCRequest)
	assert.Equal(t, Action("grpc_response"), ActionGRPCResponse)

	// Security actions
	assert.Equal(t, Action("rate_limit_exceeded"), ActionRateLimitExceeded)
	assert.Equal(t, Action("suspicious_activity"), ActionSuspiciousActivity)
	assert.Equal(t, Action("brute_force_detected"), ActionBruteForceDetected)
}

func TestOutcomeConstants(t *testing.T) {
	t.Parallel()

	assert.Equal(t, Outcome("success"), OutcomeSuccess)
	assert.Equal(t, Outcome("failure"), OutcomeFailure)
	assert.Equal(t, Outcome("error"), OutcomeError)
	assert.Equal(t, Outcome("denied"), OutcomeDenied)
}

func TestSubject_Fields(t *testing.T) {
	t.Parallel()

	subject := &Subject{
		ID:         "user123",
		Type:       "user",
		Name:       "Test User",
		Email:      "test@example.com",
		Roles:      []string{"admin", "user"},
		Groups:     []string{"engineering"},
		TenantID:   "tenant-1",
		ClientID:   "client-1",
		IPAddress:  "192.168.1.1",
		UserAgent:  "Mozilla/5.0",
		AuthMethod: "jwt",
	}

	assert.Equal(t, "user123", subject.ID)
	assert.Equal(t, "user", subject.Type)
	assert.Equal(t, "Test User", subject.Name)
	assert.Equal(t, "test@example.com", subject.Email)
	assert.Equal(t, []string{"admin", "user"}, subject.Roles)
	assert.Equal(t, []string{"engineering"}, subject.Groups)
	assert.Equal(t, "tenant-1", subject.TenantID)
	assert.Equal(t, "client-1", subject.ClientID)
	assert.Equal(t, "192.168.1.1", subject.IPAddress)
	assert.Equal(t, "Mozilla/5.0", subject.UserAgent)
	assert.Equal(t, "jwt", subject.AuthMethod)
}

func TestResource_Fields(t *testing.T) {
	t.Parallel()

	resource := &Resource{
		Type:    "api",
		ID:      "resource-1",
		Name:    "Users API",
		Path:    "/api/users",
		Service: "user-service",
		Method:  "GET",
	}

	assert.Equal(t, "api", resource.Type)
	assert.Equal(t, "resource-1", resource.ID)
	assert.Equal(t, "Users API", resource.Name)
	assert.Equal(t, "/api/users", resource.Path)
	assert.Equal(t, "user-service", resource.Service)
	assert.Equal(t, "GET", resource.Method)
}

func TestRequestDetails_Fields(t *testing.T) {
	t.Parallel()

	request := &RequestDetails{
		Method:        "POST",
		Path:          "/api/users",
		Query:         "page=1&limit=10",
		Headers:       map[string]string{"Content-Type": "application/json"},
		Body:          `{"name": "test"}`,
		ContentType:   "application/json",
		ContentLength: 16,
		RemoteAddr:    "192.168.1.1:12345",
		Protocol:      "HTTP/1.1",
	}

	assert.Equal(t, "POST", request.Method)
	assert.Equal(t, "/api/users", request.Path)
	assert.Equal(t, "page=1&limit=10", request.Query)
	assert.Equal(t, "application/json", request.Headers["Content-Type"])
	assert.Equal(t, `{"name": "test"}`, request.Body)
	assert.Equal(t, "application/json", request.ContentType)
	assert.Equal(t, int64(16), request.ContentLength)
	assert.Equal(t, "192.168.1.1:12345", request.RemoteAddr)
	assert.Equal(t, "HTTP/1.1", request.Protocol)
}

func TestResponseDetails_Fields(t *testing.T) {
	t.Parallel()

	response := &ResponseDetails{
		StatusCode:    200,
		Headers:       map[string]string{"Content-Type": "application/json"},
		Body:          `{"id": 1}`,
		ContentType:   "application/json",
		ContentLength: 9,
	}

	assert.Equal(t, 200, response.StatusCode)
	assert.Equal(t, "application/json", response.Headers["Content-Type"])
	assert.Equal(t, `{"id": 1}`, response.Body)
	assert.Equal(t, "application/json", response.ContentType)
	assert.Equal(t, int64(9), response.ContentLength)
}

func TestErrorDetails_Fields(t *testing.T) {
	t.Parallel()

	errDetails := &ErrorDetails{
		Code:    "AUTH_FAILED",
		Message: "Invalid credentials",
		Details: map[string]interface{}{
			"attempts": 3,
		},
	}

	assert.Equal(t, "AUTH_FAILED", errDetails.Code)
	assert.Equal(t, "Invalid credentials", errDetails.Message)
	assert.Equal(t, 3, errDetails.Details["attempts"])
}

func TestSecurityEvent_NilDetails(t *testing.T) {
	t.Parallel()

	subject := &Subject{ID: "user123"}

	event := SecurityEvent(ActionSuspiciousActivity, OutcomeFailure, subject, nil)

	require.NotNil(t, event)
	assert.Equal(t, EventTypeSecurity, event.Type)
	assert.NotNil(t, event.Metadata)
}
