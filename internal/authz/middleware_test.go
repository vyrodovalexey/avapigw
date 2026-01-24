package authz

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/auth"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// mockAuthorizer is a mock implementation of Authorizer for testing.
type mockAuthorizer struct {
	decision *Decision
	err      error
}

func (m *mockAuthorizer) Authorize(_ context.Context, _ *Request) (*Decision, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.decision, nil
}

func (m *mockAuthorizer) Close() error {
	return nil
}

func TestNewHTTPAuthorizer(t *testing.T) {
	t.Parallel()

	mockAuth := &mockAuthorizer{
		decision: &Decision{Allowed: true},
	}
	config := &Config{Enabled: true}

	authorizer := NewHTTPAuthorizer(mockAuth, config, WithHTTPAuthorizerMetrics(newNoopMetrics()))
	assert.NotNil(t, authorizer)
}

func TestNewHTTPAuthorizer_WithOptions(t *testing.T) {
	t.Parallel()

	mockAuth := &mockAuthorizer{
		decision: &Decision{Allowed: true},
	}
	config := &Config{Enabled: true}
	logger := observability.NopLogger()
	metrics := newNoopMetrics()

	authorizer := NewHTTPAuthorizer(mockAuth, config,
		WithHTTPAuthorizerLogger(logger),
		WithHTTPAuthorizerMetrics(metrics),
	)
	assert.NotNil(t, authorizer)
}

func TestHTTPAuthorizer_Authorize_Success(t *testing.T) {
	t.Parallel()

	mockAuth := &mockAuthorizer{
		decision: &Decision{
			Allowed: true,
			Reason:  "allowed by policy",
			Policy:  "test-policy",
		},
	}
	config := &Config{Enabled: true}

	authorizer := NewHTTPAuthorizer(mockAuth, config, WithHTTPAuthorizerMetrics(newNoopMetrics()))

	// Create request with identity in context
	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	identity := &auth.Identity{
		Subject: "user123",
		Roles:   []string{"admin"},
	}
	ctx := auth.ContextWithIdentity(req.Context(), identity)
	req = req.WithContext(ctx)

	decision, err := authorizer.Authorize(req)
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
	assert.Equal(t, "allowed by policy", decision.Reason)
	assert.Equal(t, "test-policy", decision.Policy)
}

func TestHTTPAuthorizer_Authorize_Denied(t *testing.T) {
	t.Parallel()

	mockAuth := &mockAuthorizer{
		decision: &Decision{
			Allowed: false,
			Reason:  "access denied",
			Policy:  "deny-policy",
		},
	}
	config := &Config{Enabled: true}

	authorizer := NewHTTPAuthorizer(mockAuth, config, WithHTTPAuthorizerMetrics(newNoopMetrics()))

	req := httptest.NewRequest(http.MethodDelete, "/api/admin", nil)
	identity := &auth.Identity{
		Subject: "user123",
		Roles:   []string{"guest"},
	}
	ctx := auth.ContextWithIdentity(req.Context(), identity)
	req = req.WithContext(ctx)

	decision, err := authorizer.Authorize(req)
	require.NoError(t, err)
	assert.False(t, decision.Allowed)
	assert.Equal(t, "access denied", decision.Reason)
}

func TestHTTPAuthorizer_Authorize_NoIdentity(t *testing.T) {
	t.Parallel()

	mockAuth := &mockAuthorizer{
		decision: &Decision{Allowed: true},
	}
	config := &Config{Enabled: true}

	authorizer := NewHTTPAuthorizer(mockAuth, config, WithHTTPAuthorizerMetrics(newNoopMetrics()))

	// Request without identity
	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)

	decision, err := authorizer.Authorize(req)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNoIdentity)
	assert.Nil(t, decision)
}

func TestHTTPAuthorizer_HTTPMiddleware_Allowed(t *testing.T) {
	t.Parallel()

	mockAuth := &mockAuthorizer{
		decision: &Decision{Allowed: true},
	}
	config := &Config{Enabled: true}

	authorizer := NewHTTPAuthorizer(mockAuth, config,
		WithHTTPAuthorizerLogger(observability.NopLogger()),
		WithHTTPAuthorizerMetrics(newNoopMetrics()),
	)

	// Create a test handler
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	middleware := authorizer.HTTPMiddleware()
	handler := middleware(next)

	// Create request with identity
	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	identity := &auth.Identity{Subject: "user123"}
	ctx := auth.ContextWithIdentity(req.Context(), identity)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.True(t, nextCalled)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestHTTPAuthorizer_HTTPMiddleware_Denied(t *testing.T) {
	t.Parallel()

	mockAuth := &mockAuthorizer{
		decision: &Decision{
			Allowed: false,
			Reason:  "access denied",
		},
	}
	config := &Config{Enabled: true}

	authorizer := NewHTTPAuthorizer(mockAuth, config,
		WithHTTPAuthorizerLogger(observability.NopLogger()),
		WithHTTPAuthorizerMetrics(newNoopMetrics()),
	)

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	middleware := authorizer.HTTPMiddleware()
	handler := middleware(next)

	req := httptest.NewRequest(http.MethodGet, "/api/admin", nil)
	identity := &auth.Identity{Subject: "user123"}
	ctx := auth.ContextWithIdentity(req.Context(), identity)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.False(t, nextCalled)
	assert.Equal(t, http.StatusForbidden, rr.Code)

	var response map[string]string
	err := json.NewDecoder(rr.Body).Decode(&response)
	require.NoError(t, err)
	assert.Equal(t, "access denied", response["error"])
}

func TestHTTPAuthorizer_HTTPMiddleware_NoIdentity(t *testing.T) {
	t.Parallel()

	mockAuth := &mockAuthorizer{
		decision: &Decision{Allowed: true},
	}
	config := &Config{Enabled: true}

	authorizer := NewHTTPAuthorizer(mockAuth, config,
		WithHTTPAuthorizerLogger(observability.NopLogger()),
		WithHTTPAuthorizerMetrics(newNoopMetrics()),
	)

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	middleware := authorizer.HTTPMiddleware()
	handler := middleware(next)

	// Request without identity
	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.False(t, nextCalled)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestHTTPAuthorizer_HTTPMiddleware_AuthzError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		err            error
		expectedStatus int
		expectedMsg    string
	}{
		{
			name:           "no identity error",
			err:            ErrNoIdentity,
			expectedStatus: http.StatusUnauthorized,
			expectedMsg:    "authentication required",
		},
		{
			name:           "timeout error",
			err:            ErrExternalAuthzTimeout,
			expectedStatus: http.StatusGatewayTimeout,
			expectedMsg:    "authorization timeout",
		},
		{
			name:           "unavailable error",
			err:            ErrExternalAuthzUnavailable,
			expectedStatus: http.StatusServiceUnavailable,
			expectedMsg:    "authorization service unavailable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockAuth := &mockAuthorizer{
				err: tt.err,
			}
			config := &Config{Enabled: true}

			authorizer := NewHTTPAuthorizer(mockAuth, config,
				WithHTTPAuthorizerLogger(observability.NopLogger()),
				WithHTTPAuthorizerMetrics(newNoopMetrics()),
			)

			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
			middleware := authorizer.HTTPMiddleware()
			handler := middleware(next)

			req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
			identity := &auth.Identity{Subject: "user123"}
			ctx := auth.ContextWithIdentity(req.Context(), identity)
			req = req.WithContext(ctx)

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)

			var response map[string]string
			err := json.NewDecoder(rr.Body).Decode(&response)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedMsg, response["error"])
		})
	}
}

func TestIsSensitiveHeader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		header   string
		expected bool
	}{
		{"Authorization", true},
		{"Cookie", true},
		{"Set-Cookie", true},
		{"X-Api-Key", true},
		{"X-Auth-Token", true},
		{"Proxy-Authorization", true},
		{"Content-Type", false},
		{"Accept", false},
		{"X-Request-ID", false},
		{"User-Agent", false},
	}

	for _, tt := range tests {
		t.Run(tt.header, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, isSensitiveHeader(tt.header))
		})
	}
}

func TestExtractClientIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		setupReq   func(*http.Request)
		expectedIP string
	}{
		{
			name: "X-Forwarded-For single IP",
			setupReq: func(r *http.Request) {
				r.Header.Set("X-Forwarded-For", "192.168.1.1")
			},
			expectedIP: "192.168.1.1",
		},
		{
			name: "X-Forwarded-For multiple IPs",
			setupReq: func(r *http.Request) {
				r.Header.Set("X-Forwarded-For", "192.168.1.1, 10.0.0.1, 172.16.0.1")
			},
			expectedIP: "192.168.1.1",
		},
		{
			name: "X-Real-IP",
			setupReq: func(r *http.Request) {
				r.Header.Set("X-Real-IP", "10.0.0.1")
			},
			expectedIP: "10.0.0.1",
		},
		{
			name: "RemoteAddr with port",
			setupReq: func(r *http.Request) {
				r.RemoteAddr = "192.168.1.100:12345"
			},
			expectedIP: "192.168.1.100",
		},
		{
			name: "RemoteAddr without port",
			setupReq: func(r *http.Request) {
				r.RemoteAddr = "192.168.1.100"
			},
			expectedIP: "192.168.1.100",
		},
		{
			name: "X-Forwarded-For takes precedence",
			setupReq: func(r *http.Request) {
				r.Header.Set("X-Forwarded-For", "192.168.1.1")
				r.Header.Set("X-Real-IP", "10.0.0.1")
				r.RemoteAddr = "172.16.0.1:12345"
			},
			expectedIP: "192.168.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			tt.setupReq(req)

			ip := extractClientIP(req)
			assert.Equal(t, tt.expectedIP, ip)
		})
	}
}

func TestHTTPAuthorizer_BuildRequestContext(t *testing.T) {
	t.Parallel()

	mockAuth := &mockAuthorizer{
		decision: &Decision{Allowed: true},
	}
	config := &Config{Enabled: true}

	authorizer := NewHTTPAuthorizer(mockAuth, config, WithHTTPAuthorizerMetrics(newNoopMetrics())).(*httpAuthorizer)

	req := httptest.NewRequest(http.MethodPost, "/api/users?page=1", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", "req-123")
	req.Header.Set("Authorization", "Bearer token") // Should be filtered
	req.Host = "api.example.com"
	req.RemoteAddr = "192.168.1.1:12345"

	ctx := authorizer.buildRequestContext(req)

	assert.Equal(t, "POST", ctx["method"])
	assert.Equal(t, "/api/users", ctx["path"])
	assert.Equal(t, "page=1", ctx["query"])
	assert.Equal(t, "api.example.com", ctx["host"])
	assert.Equal(t, "192.168.1.1:12345", ctx["remote_addr"])
	assert.Equal(t, "192.168.1.1", ctx["client_ip"])

	headers := ctx["headers"].(map[string]string)
	assert.Equal(t, "application/json", headers["Content-Type"])
	// Note: Go's http package canonicalizes header names, so X-Request-ID becomes X-Request-Id
	assert.Equal(t, "req-123", headers["X-Request-Id"])
	_, hasAuth := headers["Authorization"]
	assert.False(t, hasAuth, "Authorization header should be filtered")
}
